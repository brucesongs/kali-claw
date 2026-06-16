# Satellite Signal Analysis Guide

## Introduction

Satellite signals provide a rich and accessible target for Software Defined Radio analysis. Unlike terrestrial radio systems that require proximity to the transmitter, satellite signals blanket large portions of the Earth's surface and can be received with modest antenna setups and RTL-SDR dongles. The three primary categories of accessible satellite signals relevant to security assessment are AIS (Automatic Identification System) for maritime vessel tracking, ADS-B (Automatic Dependent Surveillance-Broadcast) for aircraft monitoring, and NOAA weather satellite imagery transmissions.

Each of these systems was designed with different security assumptions. AIS was designed for collision avoidance, not privacy, yet vessel operators sometimes disable transponders to evade detection. ADS-B was designed for air traffic management with no authentication, creating potential for spoofing and injection attacks that could affect flight safety systems. NOAA weather satellite transmissions are unencrypted public broadcasts, but analyzing them builds skills transferable to assessing satellite communication systems used in critical infrastructure.

This guide covers satellite signal capture using cost-effective SDR hardware, AIS ship tracking and anomaly detection, ADS-B aircraft monitoring and security assessment, and NOAA weather satellite image decoding. All receive-only activities are legal in most jurisdictions, but transmitting on satellite frequencies requires explicit licensing. Any ADS-B or AIS injection testing must be conducted in Faraday cage environments to prevent interference with safety-critical systems.

**Objectives**: Master satellite signal reception and analysis with SDR equipment, implement AIS vessel tracking and anomaly detection, perform ADS-B aircraft monitoring and assess injection vulnerabilities, decode NOAA weather satellite imagery, and understand satellite communication security considerations.

## Part 1: AIS Ship Tracking and Analysis

### AIS Signal Structure

AIS (Automatic Identification System) operates on two VHF channels: 161.975 MHz (Channel A, AIS1) and 162.025 MHz (Channel B, AIS2). Ships broadcast their identity, position, course, speed, and navigation status at intervals ranging from 2 seconds (moving fast) to 3 minutes (at anchor). The protocol uses Gaussian Minimum Shift Keying (GMSK) modulation at 9600 baud with HDLC framing.

```python
#!/usr/bin/env python3
"""AIS Ship Tracking System - Receive and decode AIS signals.

Captures AIS transmissions using RTL-SDR and decodes ship position,
identity, course, and speed. Includes anomaly detection for security
assessment of maritime tracking systems.
"""

import subprocess
import json
import math
from datetime import datetime
from collections import defaultdict


class AISDecoder:
    """Decode AIS messages from raw signal or network data."""

    # AIS Message Types
    MESSAGE_TYPES = {
        1: "Position Report Class A",
        2: "Position Report Class A (Assigned schedule)",
        3: "Position Report Class A (Response to interrogation)",
        4: "Base Station Report",
        5: "Static and Voyage Related Data",
        9: "SAR Aircraft Position Report",
        18: "Standard Class B CS Position Report",
        19: "Extended Class B CS Position Report",
        21: "Aid-to-Navigation Report",
        24: "Class B CS Static Data Report",
        27: "Long Range AIS Broadcast message"
    }

    # Navigation Status for Message Types 1/2/3
    NAV_STATUS = {
        0: "Under way using engine",
        1: "At anchor",
        2: "Not under command",
        3: "Restricted manoeuvrability",
        4: "Constrained by her draught",
        5: "Moored",
        6: "Aground",
        7: "Engaged in fishing",
        8: "Under way sailing",
        9: "Reserved for future amendment",
        15: "Not defined"
    }

    def __init__(self):
        self.vessels = {}  # MMSI -> vessel data
        self.message_log = []
        self.anomalies = []

    def decode_position_report(self, payload_bits):
        """Decode AIS Message Type 1/2/3 (Position Report Class A).

        Extracts: MMSI, navigation status, speed over ground,
        position (lat/lon), course over ground, heading, timestamp.
        """
        # Message type (6 bits)
        msg_type = self._bits_to_int(payload_bits[0:6])

        # MMSI (30 bits) - Maritime Mobile Service Identity
        mmsi_raw = self._bits_to_int(payload_bits[8:38])
        mmsi = str(mmsi_raw).zfill(9)

        # Navigation status (4 bits)
        nav_status = self._bits_to_int(payload_bits[38:42])

        # Speed over ground (10 bits, in 0.1 knots)
        sog_raw = self._bits_to_int(payload_bits[50:60])
        sog = sog_raw / 10.0

        # Position accuracy (1 bit)
        position_accuracy = payload_bits[60]

        # Longitude (28 bits, signed, in 0.0001 minutes)
        lon_raw = self._bits_to_signed_int(payload_bits[61:89])
        longitude = lon_raw / 10000.0 / 60.0

        # Latitude (27 bits, signed, in 0.0001 minutes)
        lat_raw = self._bits_to_signed_int(payload_bits[89:116])
        latitude = lat_raw / 10000.0 / 60.0

        # Course over ground (12 bits, in 0.1 degrees)
        cog_raw = self._bits_to_int(payload_bits[116:128])
        cog = cog_raw / 10.0

        # True heading (9 bits)
        heading_raw = self._bits_to_int(payload_bits[128:137])
        heading = heading_raw if heading_raw != 511 else None

        # Timestamp (6 bits)
        timestamp = self._bits_to_int(payload_bits[137:143])

        vessel = {
            "mmsi": mmsi,
            "message_type": msg_type,
            "type_name": self.MESSAGE_TYPES.get(msg_type, "Unknown"),
            "nav_status": self.NAV_STATUS.get(nav_status, f"Unknown ({nav_status})"),
            "speed_knots": round(sog, 1),
            "latitude": round(latitude, 6),
            "longitude": round(longitude, 6),
            "course": round(cog, 1),
            "heading": heading,
            "timestamp_second": timestamp,
            "decoded_at": datetime.now().isoformat()
        }

        return vessel

    def decode_static_data(self, payload_bits):
        """Decode AIS Message Type 5 (Static and Voyage Related Data).

        Extracts: MMSI, vessel name, call sign, ship type,
        dimensions, destination, ETA.
        """
        mmsi_raw = self._bits_to_int(payload_bits[8:38])
        mmsi = str(mmsi_raw).zfill(9)

        # AIS version (2 bits)
        ais_version = self._bits_to_int(payload_bits[38:40])

        # IMO number (30 bits)
        imo = self._bits_to_int(payload_bits[40:70])

        # Call sign (42 bits, 6-bit ASCII)
        call_sign = self._decode_string(payload_bits[70:112], 7)

        # Vessel name (120 bits, 6-bit ASCII)
        vessel_name = self._decode_string(payload_bits[112:232], 20).strip()

        # Ship type (8 bits)
        ship_type = self._bits_to_int(payload_bits[232:240])

        # Dimension to bow (9 bits), stern (9 bits), port (6 bits), starboard (6 bits)
        dim_bow = self._bits_to_int(payload_bits[240:249])
        dim_stern = self._bits_to_int(payload_bits[249:258])
        dim_port = self._bits_to_int(payload_bits[258:264])
        dim_starboard = self._bits_to_int(payload_bits[264:270])

        length = dim_bow + dim_stern
        beam = dim_port + dim_starboard

        # Destination (120 bits, 6-bit ASCII)
        destination = self._decode_string(payload_bits[302:422], 20).strip()

        static_data = {
            "mmsi": mmsi,
            "imo": imo if imo != 0 else None,
            "call_sign": call_sign,
            "vessel_name": vessel_name,
            "ship_type_code": ship_type,
            "length_meters": length if length < 2000 else None,
            "beam_meters": beam if beam < 500 else None,
            "destination": destination,
            "decoded_at": datetime.now().isoformat()
        }

        return static_data

    def update_vessel_database(self, vessel_data):
        """Update the vessel tracking database with new data."""
        mmsi = vessel_data["mmsi"]

        if mmsi not in self.vessels:
            self.vessels[mmsi] = {
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "position_count": 0
            }

        vessel = self.vessels[mmsi]
        vessel["last_seen"] = datetime.now().isoformat()
        vessel["position_count"] = vessel.get("position_count", 0) + 1

        # Update position data
        for key in ["latitude", "longitude", "speed_knots", "course", "heading", "nav_status"]:
            if key in vessel_data:
                vessel[key] = vessel_data[key]

        # Update static data
        for key in ["vessel_name", "call_sign", "imo", "ship_type_code", "destination"]:
            if key in vessel_data:
                vessel[key] = vessel_data[key]

        return vessel

    def detect_anomalies(self):
        """Detect anomalous vessel behavior.

        Checks for:
        - Impossible speed changes (unrealistic acceleration)
        - Position jumps (teleportation)
        - MMSI format anomalies
        - Navigation status inconsistencies
        """
        for mmsi, vessel in self.vessels.items():
            # Check MMSI format
            if len(mmsi) != 9:
                self.anomalies.append({
                    "type": "invalid_mmsi",
                    "mmsi": mmsi,
                    "detail": f"Invalid MMSI length: {len(mmsi)} digits"
                })

            # Check for impossible speeds (> 60 knots for civilian vessels)
            speed = vessel.get("speed_knots", 0)
            if speed > 60:
                self.anomalies.append({
                    "type": "impossible_speed",
                    "mmsi": mmsi,
                    "vessel_name": vessel.get("vessel_name", "Unknown"),
                    "speed": speed,
                    "detail": f"Speed {speed} knots exceeds realistic maximum"
                })

            # Check for suspicious navigation status combinations
            nav_status = vessel.get("nav_status", "")
            speed = vessel.get("speed_knots", 0)
            if "Moored" in nav_status and speed > 2:
                self.anomalies.append({
                    "type": "status_speed_mismatch",
                    "mmsi": mmsi,
                    "nav_status": nav_status,
                    "speed": speed,
                    "detail": f"Vessel reports moored but moving at {speed} knots"
                })

        return self.anomalies

    def _bits_to_int(self, bits):
        """Convert a list of bits to an unsigned integer."""
        return int(''.join(str(b) for b in bits), 2)

    def _bits_to_signed_int(self, bits):
        """Convert a list of bits to a signed integer (two's complement)."""
        value = int(''.join(str(b) for b in bits), 2)
        if bits[0] == 1:  # Negative number
            value -= (1 << len(bits))
        return value

    def _decode_string(self, bits, max_chars):
        """Decode 6-bit ASCII AIS text field."""
        AIS_6BIT_CHARS = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^- !\"#$%&'()*+,-./0123456789:;<=>?"
        result = ""
        for i in range(0, len(bits), 6):
            if i + 6 <= len(bits):
                char_val = self._bits_to_int(bits[i:i+6])
                if char_val < len(AIS_6BIT_CHARS):
                    result += AIS_6BIT_CHARS[char_val]
        return result


def capture_ais(interface="rtlais", frequency=162000000):
    """Start AIS signal reception using rtl_ais or similar tool.

    AIS uses two channels: 161.975 MHz and 162.025 MHz.
    rtl_ais can receive both simultaneously.
    """
    print("[*] AIS Signal Reception")
    print(f"    Channel A: 161.975 MHz")
    print(f"    Channel B: 162.025 MHz")
    print(f"    Modulation: GMSK at 9600 baud")
    print(f"    Required hardware: RTL-SDR with VHF antenna")
    print()
    print("    Start reception with:")
    print("    rtl_ais -l 161.975M -r 162.025M")
    print()
    print("    Or use GNURadio AIS decoder flowgraph:")
    print("    gnuradio-companion ais_decoder.grc")
    print()
    print("    Alternative: use aisdecoder to process raw I/Q:")
    print("    rtl_sdr -f 161975000 -s 960000 -g 40 - | aisdecoder -h 127.0.0.1 -p 10110")
    print()
    print("    Feed decoded data to this script via UDP or parse NMEA sentences")
    print("    from the AIS decoder output.")


if __name__ == "__main__":
    decoder = AISDecoder()
    print("AIS Ship Tracking System")
    print("=" * 50)
    print()
    capture_ais()

    # Demonstrate anomaly detection with sample data
    print("\n[*] Anomaly Detection Demo:")
    sample_vessel = {
        "mmsi": "123456789",
        "latitude": 51.5074,
        "longitude": -0.1278,
        "speed_knots": 35.2,
        "course": 45.0,
        "nav_status": "Under way using engine"
    }
    decoder.update_vessel_database(sample_vessel)
    print(f"    Vessel tracked: MMSI {sample_vessel['mmsi']}")
    print(f"    Position: ({sample_vessel['latitude']}, {sample_vessel['longitude']})")
    print(f"    Speed: {sample_vessel['speed_knots']} knots, Course: {sample_vessel['course']}")

    anomalies = decoder.detect_anomalies()
    if anomalies:
        print(f"\n    Anomalies detected: {len(anomalies)}")
        for a in anomalies:
            print(f"    [{a['type']}] {a['detail']}")
    else:
        print("    No anomalies detected")
```

## Part 2: ADS-B Aircraft Monitoring and Security Assessment

### ADS-B Signal Structure

ADS-B (Automatic Dependent Surveillance-Broadcast) operates at 1090 MHz using Pulse Position Modulation (PPM). Aircraft broadcast their position, velocity, identity, and altitude approximately once per second. The protocol has no authentication, meaning anyone with a suitable receiver can track aircraft, and anyone with a suitable transmitter could theoretically inject false data.

```python
#!/usr/bin/env python3
"""ADS-B Aircraft Monitoring and Security Assessment.

Receives and decodes ADS-B messages at 1090 MHz using RTL-SDR.
Monitors aircraft positions, detects anomalies, and assesses
the security of ADS-B implementations.
"""

import subprocess
import json
import math
from datetime import datetime
from collections import defaultdict


class ADSBDecoder:
    """Decode ADS-B (1090 MHz) messages for aircraft tracking."""

    # ADS-B Message Type Classification
    DF_TYPES = {
        0: "Short Air-Air Surveillance",
        4: "Surveillance Altitude Reply",
        5: "Surveillance Identity Reply",
        11: "All Call Reply",
        16: "Long Air-Air Surveillance",
        17: "ADS-B Extended Squitter (DF=17)",
        18: "Extended Squitter (Non-Transponder)",
        19: "Military Extended Squitter",
        20: "Comm-B Altitude Reply",
        21: "Comm-B Identity Reply",
        24: "Comm-D Elaborate Message"
    }

    # ADS-B Type Codes (within DF=17 messages)
    ADSB_TYPE_CODES = {
        (1, 4): "Aircraft Identification",
        (5, 8): "Surface Position",
        (9, 18): "Airborne Position (Baro Altitude)",
        (19, 22): "Airborne Velocity",
        (20, 22): "Airborne Position (GNSS Height)",
        (23, 31): "Reserved / Other"
    }

    # Aircraft category descriptions
    AIRCRAFT_CATEGORIES = {
        1: "Light (< 15500 lbs)",
        2: "Small (15500-75000 lbs)",
        3: "Large (75000-300000 lbs)",
        4: "High Vortex Large",
        5: "Heavy (> 300000 lbs)",
        6: "High Performance",
        7: "Rotorcraft",
        8: "Glider/Sailplane"
    }

    def __init__(self):
        self.aircraft = {}  # ICAO hex -> aircraft data
        self.message_count = defaultdict(int)
        self.anomalies = []
        self.spoofing_indicators = []

    def decode_aircraft_identification(self, hex_msg):
        """Decode ADS-B aircraft identification message (TC 1-4).

        Extracts ICAO address, callsign, and aircraft category.
        """
        msg = int(hex_msg, 16)

        # DF=17 check
        df = (msg >> 88) & 0x1F
        if df != 17:
            return None

        # Capability (3 bits)
        capability = (msg >> 85) & 0x07

        # ICAO address (24 bits)
        icao = (msg >> 48) & 0xFFFFFF
        icao_hex = f"{icao:06X}"

        # Type code (5 bits)
        tc = (msg >> 48) & 0x1F

        # Aircraft category (3 bits)
        category = (msg >> 45) & 0x07

        # Callsign (8 characters, 6 bits each)
        callsign = ""
        for i in range(8):
            char_bits = (msg >> (42 - i * 6)) & 0x3F
            if 0x20 <= char_bits <= 0x5F:
                callsign += chr(char_bits)
            elif 0x01 <= char_bits <= 0x1A:
                callsign += chr(char_bits + 0x40)
            else:
                callsign += " "

        callsign = callsign.strip()

        result = {
            "icao": icao_hex,
            "callsign": callsign,
            "category": category,
            "category_desc": self.AIRCRAFT_CATEGORIES.get(category, f"Category {category}"),
            "type_code": tc,
            "decoded_at": datetime.now().isoformat()
        }

        return result

    def decode_airborne_position(self, hex_msg, even_odd):
        """Decode ADS-B airborne position message (TC 9-18).

        Extracts altitude, latitude, and longitude.
        Requires paired even/odd messages for full position decode.
        """
        msg = int(hex_msg, 16)

        # ICAO address
        icao = (msg >> 48) & 0xFFFFFF
        icao_hex = f"{icao:06X}"

        # Altitude (12 bits)
        alt_bits = (msg >> 36) & 0x1FFF

        # Decode altitude (either Gillham coded or direct)
        if alt_bits & 0x40:  # M-bit set -> metric altitude
            altitude_m = (alt_bits & 0x3F) | ((alt_bits & 0x1F00) >> 1)
            altitude_ft = round(altitude_m * 3.28084)
        else:  # Gillham coded (100 ft increments)
            n_bit = (alt_bits >> 4) & 0x01
            alt_100 = ((alt_bits & 0x1F80) >> 3) | ((alt_bits & 0x20) >> 2) | ((alt_bits & 0x10) >> 1)
            altitude_ft = alt_100 * 100 - 1000 if alt_100 > 0 else 0

        # CPR encoded position
        lat_cpr = (msg >> 17) & 0x1FFFF
        lon_cpr = (msg >> 0) & 0x3FFFF

        position = {
            "icao": icao_hex,
            "altitude_ft": altitude_ft,
            "lat_cpr": lat_cpr / 131072.0,
            "lon_cpr": lon_cpr / 131072.0,
            "format": "even" if even_odd == 0 else "odd",
            "decoded_at": datetime.now().isoformat()
        }

        return position

    def decode_airborne_velocity(self, hex_msg):
        """Decode ADS-B airborne velocity message (TC 19).

        Extracts speed, heading, vertical rate.
        """
        msg = int(hex_msg, 16)

        icao = (msg >> 48) & 0xFFFFFF
        icao_hex = f"{icao:06X}"

        # Subtype (1 = ground speed, 2 = airspeed)
        subtype = (msg >> 48) & 0x07

        # Intent change, IFR capability
        ic = (msg >> 47) & 0x01

        # Velocity (signed)
        ew_sign = (msg >> 42) & 0x01
        ew_vel = (msg >> 33) & 0x1FF
        ns_sign = (msg >> 41) & 0x01
        ns_vel = (msg >> 30) & 0x1FF

        if subtype == 1:  # Ground speed
            ew_vel = ew_vel - 1 if ew_sign else ew_vel - 1
            ns_vel = ns_vel - 1 if ns_sign else ns_vel - 1
            speed_knots = math.sqrt(ew_vel**2 + ns_vel**2)
            heading = math.degrees(math.atan2(ew_vel, ns_vel)) % 360
        else:
            speed_knots = None
            heading = None

        # Vertical rate
        vr_sign = (msg >> 25) & 0x01
        vr_raw = (msg >> 19) & 0x3F
        vertical_rate = (vr_raw - 1) * 64 if vr_raw else 0
        if vr_sign:
            vertical_rate = -vertical_rate

        velocity = {
            "icao": icao_hex,
            "subtype": "ground_speed" if subtype == 1 else "airspeed",
            "speed_knots": round(speed_knots, 1) if speed_knots else None,
            "heading": round(heading, 1) if heading else None,
            "vertical_rate_fpm": vertical_rate,
            "decoded_at": datetime.now().isoformat()
        }

        return velocity

    def update_aircraft_database(self, data):
        """Update aircraft tracking database with decoded data."""
        icao = data.get("icao")
        if not icao:
            return

        if icao not in self.aircraft:
            self.aircraft[icao] = {
                "icao": icao,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "msg_count": 0
            }

        aircraft = self.aircraft[icao]
        aircraft["last_seen"] = datetime.now().isoformat()
        aircraft["msg_count"] += 1

        for key in ["callsign", "category", "category_desc", "altitude_ft",
                     "latitude", "longitude", "speed_knots", "heading",
                     "vertical_rate_fpm"]:
            if key in data and data[key] is not None:
                aircraft[key] = data[key]

    def detect_adsb_anomalies(self):
        """Detect anomalous ADS-B messages that may indicate spoofing.

        Checks for:
        - Impossible flight parameters
        - Conflicting position/identity data
        - Multiple aircraft with same callsign
        - Unrealistic speed/altitude combinations
        - Position jumps exceeding possible travel distance
        """
        for icao, aircraft in self.aircraft.items():
            speed = aircraft.get("speed_knots")
            alt = aircraft.get("altitude_ft")

            # Check for impossible speed (> Mach 3 for civilian aircraft)
            if speed and speed > 2000:
                self.anomalies.append({
                    "type": "impossible_speed",
                    "icao": icao,
                    "callsign": aircraft.get("callsign", "Unknown"),
                    "speed_knots": speed,
                    "detail": f"Speed {speed} knots exceeds Mach 3 - possible spoofing"
                })

            # Check for impossible altitude (> 60,000 ft for civilian)
            if alt and alt > 60000:
                self.anomalies.append({
                    "type": "impossible_altitude",
                    "icao": icao,
                    "callsign": aircraft.get("callsign", "Unknown"),
                    "altitude_ft": alt,
                    "detail": f"Altitude {alt} ft exceeds civilian ceiling"
                })

            # Check for ground speed > 0 at altitude > 0 with no position
            if speed and speed > 0 and not aircraft.get("latitude"):
                self.anomalies.append({
                    "type": "speed_without_position",
                    "icao": icao,
                    "speed_knots": speed,
                    "detail": "Aircraft reporting speed but no position data"
                })

        return self.anomalies


def setup_adsb_reception():
    """Set up ADS-B signal reception using dump1090 or similar."""
    print("[*] ADS-B Reception Setup")
    print("=" * 50)
    print()
    print("Hardware required:")
    print("  - RTL-SDR dongle (any variant)")
    print("  - 1090 MHz antenna (or a simple wire antenna cut to ~13.8 cm)")
    print()
    print("Software options:")
    print()
    print("  1. dump1090 (most popular, includes web interface):")
    print("     dump1090 --net --interactive")
    print("     Web interface: http://localhost:8080")
    print()
    print("  2. dump1090-mutability (enhanced version):")
    print("     dump1090-mutability --net --gain 40")
    print()
    print("  3. rtl_adsb (minimal, included with RTL-SDR):")
    print("     rtl_adsb -g 40 | python3 adsb_decoder.py")
    print()
    print("  4. GNURadio ADS-B flowgraph:")
    print("     gnuradio-companion adsb_decoder.grc")
    print()
    print("  5. ReadBeast (high-performance decoder):")
    print("     readbeast --net --modeac --net-http-port 8080")
    print()
    print("Signal parameters:")
    print("  Frequency: 1090.000 MHz")
    print("  Modulation: PPM (Pulse Position Modulation)")
    print("  Data rate: 1 Mbit/s")
    print("  Message length: 56 or 112 bits")
    print("  Transmit power: typically 20-500W from aircraft")
    print("  Reception range: up to 300+ km with good antenna")


if __name__ == "__main__":
    decoder = ADSBDecoder()
    print("ADS-B Aircraft Monitoring and Security Assessment")
    print("=" * 55)
    print()
    setup_adsb_reception()

    print("\n\n[*] ADS-B Security Assessment Notes:")
    print("    - ADS-B has no authentication mechanism")
    print("    - Messages can be received by anyone with an SDR")
    print("    - Theoretical injection of false aircraft data is possible")
    print("    - ADS-B INJECTION TESTING MUST BE DONE IN FARADAY CAGE ONLY")
    print("    - Interfering with aircraft safety systems is a federal crime")
    print()
    print("    Known ADS-B vulnerabilities (for assessment awareness):")
    print("    1. No message authentication")
    print("    2. No encryption of position/identity data")
    print("    3. Aircraft can be tracked worldwide by anyone")
    print("    4. Ghost aircraft injection (requires controlled environment)")
    print("    5. ADS-B denial of service through jamming")
    print("    6. Altitude/spoofing to confuse conflict detection systems")
```

## Part 3: NOAA Weather Satellite Decoding

### NOAA Satellite Overview

NOAA operates polar-orbiting weather satellites (NOAA-15, NOAA-18, NOAA-19) that broadcast Automatic Picture Transmission (APT) images at 137 MHz. These are unencrypted analog transmissions that can be decoded with an RTL-SDR and appropriate software. The APT signal uses amplitude modulation of a 2400 Hz subcarrier, producing images at 4 km resolution with two channels: visible and infrared.

```python
#!/usr/bin/env python3
"""NOAA Weather Satellite APT Image Decoder.

Receives and decodes NOAA APT weather satellite transmissions
at 137 MHz using RTL-SDR. Produces visible and infrared images.
"""

import numpy as np
from datetime import datetime, timedelta


class NOAAFrequencyTable:
    """NOAA satellite frequencies and pass prediction."""

    SATELLITES = {
        "NOAA-15": {
            "frequency": 137620000,  # 137.620 MHz
            "status": "Active",
            "orbit_height_km": 830,
            "inclination": 98.7,
            "apt_channels": ["Visible (Channel 2)", "Infrared (Channel 4)"],
            "apt_resolution_km": 4,
            "apt_line_rate": 2  # lines per second
        },
        "NOAA-18": {
            "frequency": 137912500,  # 137.9125 MHz
            "status": "Active",
            "orbit_height_km": 854,
            "inclination": 99.0,
            "apt_channels": ["Visible (Channel 2)", "Infrared (Channel 4)"],
            "apt_resolution_km": 4,
            "apt_line_rate": 2
        },
        "NOAA-19": {
            "frequency": 137100000,  # 137.100 MHz
            "status": "Active",
            "orbit_height_km": 870,
            "inclination": 99.2,
            "apt_channels": ["Visible (Channel 2)", "Infrared (Channel 4)"],
            "apt_resolution_km": 4,
            "apt_line_rate": 2
        }
    }

    @classmethod
    def get_frequency_table(cls):
        """Print NOAA satellite frequency table."""
        print("NOAA Weather Satellite APT Frequency Table")
        print("=" * 55)
        for name, info in cls.SATELLITES.items():
            freq_mhz = info["frequency"] / 1e6
            print(f"\n  {name}: {freq_mhz:.4f} MHz")
            print(f"    Status: {info['status']}")
            print(f"    Orbit: {info['orbit_height_km']} km")
            print(f"    Channels: {', '.join(info['apt_channels'])}")
            print(f"    Resolution: {info['apt_resolution_km']} km")
            print(f"    Line rate: {info['apt_line_rate']} lines/second")

    @classmethod
    def get_capture_parameters(cls, satellite_name):
        """Get capture parameters for a specific NOAA satellite."""
        sat = cls.SATELLITES.get(satellite_name)
        if not sat:
            print(f"[!] Unknown satellite: {satellite_name}")
            return None

        params = {
            "frequency": sat["frequency"],
            "sample_rate": 11025 * 4,  # Oversample for better demodulation
            "bandwidth": 40000,  # 40 kHz bandwidth for APT
            "duration_seconds": 900,  # 15 minutes typical pass
            "modulation": "AM (APT uses amplitude modulation of 2400 Hz subcarrier)"
        }

        print(f"\n[*] Capture parameters for {satellite_name}:")
        print(f"    Frequency: {params['frequency']/1e6:.4f} MHz")
        print(f"    Sample rate: {params['sample_rate']} SPS")
        print(f"    Bandwidth: {params['bandwidth']} Hz")
        print(f"    Duration: {params['duration_seconds']} seconds (15 min pass)")
        print(f"    Modulation: {params['modulation']}")

        return params


class APTDecoder:
    """Decode NOAA APT audio signal into weather images."""

    def __init__(self, audio_file, sample_rate=11025):
        """Initialize with demodulated APT audio signal.

        Args:
            audio_file: WAV file of demodulated APT signal
            sample_rate: Audio sample rate (typically 11025 Hz)
        """
        self.sample_rate = sample_rate
        self.line_rate = 2  # NOAA APT: 2 lines per second
        self.samples_per_line = sample_rate // self.line_rate

        # Load audio data
        try:
            import wave
            with wave.open(audio_file, 'rb') as wf:
                self.audio = np.frombuffer(
                    wf.readframes(wf.getnframes()),
                    dtype=np.int16
                ).astype(np.float32) / 32768.0
        except Exception:
            # Fallback: load raw float data
            self.audio = np.fromfile(audio_file, dtype=np.float32)

        print(f"[*] Loaded APT audio: {len(self.audio)} samples "
              f"({len(self.audio)/sample_rate:.1f} seconds)")

    def sync_and_decode(self):
        """Synchronize to APT sync pattern and decode image.

        APT frame structure:
        - Sync A (7 pulses at 1040 Hz, 832 samples): Channel A marker
        - Space (black reference)
        - Image data A (909 pixels per line)
        - Telemetry (wedge pattern)
        - Sync B (7 pulses at 832 Hz, 832 samples): Channel B marker
        - Space (black reference)
        - Image data B (909 pixels per line)
        - Telemetry (wedge pattern)
        """
        # Downconvert: extract AM envelope
        envelope = np.abs(self.audio)

        # Low-pass filter to extract image data
        from scipy.signal import butter, filtfilt
        nyquist = self.sample_rate / 2
        cutoff = 2080 / nyquist  # APT pixel rate ~2080 Hz
        b, a = butter(4, cutoff, btype='low')
        filtered = filtfilt(b, a, envelope)

        # Normalize
        filtered = (filtered - np.min(filtered)) / (np.max(filtered) - np.min(filtered))
        filtered = (filtered * 255).astype(np.uint8)

        # Calculate image dimensions
        num_lines = len(filtered) // self.samples_per_line
        image = np.zeros((num_lines, self.samples_per_line), dtype=np.uint8)

        for line in range(num_lines):
            start = line * self.samples_per_line
            end = start + self.samples_per_line
            if end <= len(filtered):
                image[line, :] = filtered[start:end]

        # Split into Channel A (visible) and Channel B (infrared)
        mid = self.samples_per_line // 2
        channel_a = image[:, :mid]
        channel_b = image[:, mid:]

        print(f"[*] Decoded image: {num_lines} lines")
        print(f"    Channel A (visible): {channel_a.shape}")
        print(f"    Channel B (infrared): {channel_b.shape}")

        return {
            "full_image": image,
            "channel_a_visible": channel_a,
            "channel_b_infrared": channel_b,
            "num_lines": num_lines,
            "samples_per_line": self.samples_per_line
        }


def setup_noaa_reception():
    """Set up NOAA weather satellite reception."""
    print("[*] NOAA Weather Satellite Reception Setup")
    print("=" * 55)
    print()
    print("Hardware required:")
    print("  - RTL-SDR dongle")
    print("  - VHF antenna (137 MHz)")
    print("    Recommended: Quadrifilar helix (QFH) or V-dipole antenna")
    print("    Simple option: Two 52 cm wire elements in V-shape")
    print()
    print("Antenna construction (V-dipole for 137 MHz):")
    print("  - Each element: 52 cm (half-wavelength at 137 MHz)")
    print("  - Angle between elements: 120 degrees")
    print("  - Connect to RTL-SDR via 75 ohm coax")
    print()
    print("Capture procedure:")
    print("  1. Predict satellite pass using Gpredict or N2YO.com")
    print("  2. Start capture when satellite rises above 15 degrees elevation")
    print("  3. Capture for 10-15 minutes during the pass")
    print()
    print("Capture commands:")
    print("  # NOAA-19 (137.100 MHz)")
    print("  rtl_fm -f 137100000 -s 44100 -g 40 -E wav -E deemp \\")
    print("    -F 9 - | sox -t raw -r 44100 -b 16 -e signed-integer - - noaa19.wav")
    print()
    print("  # NOAA-15 (137.620 MHz)")
    print("  rtl_fm -f 137620000 -s 44100 -g 40 -E wav -E deemp \\")
    print("    -F 9 - | sox -t raw -r 44100 -b 16 -e signed-integer - - noaa15.wav")
    print()
    print("Decode with wxtoimg:")
    print("  wxtoimg -t n noaa19.wav noaa19_visible.png   # Visible image")
    print("  wxtoimg -t i noaa19.wav noaa19_ir.png        # Infrared image")
    print("  wxtoimg -t HVCT noaa19.wav noaa19_hvct.png   # Color enhancement")
    print()
    print("Or decode with APTDecoder:")
    print("  python3 -c \"from sat_guide import APTDecoder; \\")
    print("    dec = APTDecoder('noaa19.wav'); dec.sync_and_decode()\"")


if __name__ == "__main__":
    print("NOAA Weather Satellite Signal Analysis")
    print("=" * 45)
    print()
    NOAAFrequencyTable.get_frequency_table()
    print()
    setup_noaa_reception()
```

## Part 4: Satellite Communication Security Considerations

### Threat Model for Satellite Systems

```python
#!/usr/bin/env python3
"""Satellite Communication Security Assessment Framework.

Provides a structured security assessment methodology for
satellite communication systems accessible via SDR.
"""

SATELLITE_THREAT_MODEL = {
    "ais_maritime": {
        "system": "AIS (Automatic Identification System)",
        "frequency": "161.975 / 162.025 MHz (VHF)",
        "threats": [
            {
                "threat": "Vessel tracking and intelligence gathering",
                "difficulty": "TRIVIAL",
                "impact": "Privacy violation, commercial intelligence",
                "description": "Anyone with an RTL-SDR can track all AIS-equipped vessels",
                "mitigation": "No technical mitigation - AIS is designed to be public"
            },
            {
                "threat": "AIS spoofing / ghost vessels",
                "difficulty": "MEDIUM",
                "impact": "Maritime confusion, collision risk, smuggling cover",
                "description": "Inject false vessel positions to create ghost ships or mask real positions",
                "mitigation": "Cross-reference with radar/satellite imagery, message timing analysis"
            },
            {
                "threat": "AIS denial of service (jamming)",
                "difficulty": "LOW",
                "impact": "Loss of vessel tracking in affected area",
                "description": "Jam VHF channels 87B and 88B to prevent AIS reception",
                "mitigation": "Satellite-based AIS receivers (detect from above), frequency monitoring"
            },
            {
                "threat": "Vessel transponder manipulation",
                "difficulty": "LOW",
                "impact": "Identity fraud, sanctions evasion",
                "description": "Vessels modify their MMSI, name, or flag in AIS broadcasts",
                "mitigation": "Cross-reference MMSI with ITU database, verify vessel signatures"
            }
        ]
    },
    "adsb_aviation": {
        "system": "ADS-B (Aircraft Surveillance)",
        "frequency": "1090 MHz",
        "threats": [
            {
                "threat": "Aircraft tracking and surveillance",
                "difficulty": "TRIVIAL",
                "impact": "Privacy violation, military intelligence",
                "description": "Anyone can track ADS-B equipped aircraft worldwide",
                "mitigation": "Military aircraft use encrypted Mode 5, ADS-B can be disabled"
            },
            {
                "threat": "Ghost aircraft injection",
                "difficulty": "MEDIUM",
                "impact": "ATC confusion, potential collision avoidance trigger",
                "description": "Inject false 1090 MHz messages to create phantom aircraft",
                "mitigation": "Multi-lateration verification, ADS-B cryptographic standards (future)"
            },
            {
                "threat": "Aircraft disappearance (message suppression)",
                "difficulty": "MEDIUM",
                "impact": "Loss of aircraft tracking",
                "description": "Jam or selectively delete aircraft ADS-B messages",
                "mitigation": "Multi-receiver correlation, primary radar backup"
            }
        ]
    },
    "satellite_downlink": {
        "system": "Satellite Downlink Communications",
        "frequency": "Various (L-band, S-band, C-band, Ku-band)",
        "threats": [
            {
                "threat": "Satellite signal interception",
                "difficulty": "LOW to MEDIUM",
                "impact": "Intelligence gathering, data theft",
                "description": "Intercept unencrypted satellite downlink transmissions",
                "mitigation": "Encrypt all satellite data links, use DVB-S2 encryption"
            },
            {
                "threat": "GPS spoofing (satellite navigation)",
                "difficulty": "MEDIUM",
                "impact": "Navigation confusion, timing disruption",
                "description": "Transmit fake GPS signals to override legitimate satellite signals",
                "mitigation": "GPS authentication (NDS), multi-constellation verification"
            },
            {
                "threat": "Satellite uplink hijacking",
                "difficulty": "HIGH to VERY HIGH",
                "impact": "Satellite control compromise",
                "description": "Transmit unauthorized commands to satellite on uplink frequency",
                "mitigation": "Encrypted command links, authenticated uplink, geographic verification"
            }
        ]
    }
}


def print_threat_assessment():
    """Print comprehensive satellite threat assessment."""
    print("=" * 70)
    print("SATELLITE COMMUNICATION SECURITY THREAT ASSESSMENT")
    print("=" * 70)

    for category, data in SATELLITE_THREAT_MODEL.items():
        print(f"\n{'='*60}")
        print(f"System: {data['system']}")
        print(f"Frequency: {data['frequency']}")
        print(f"{'='*60}")

        for threat in data["threats"]:
            print(f"\n  [{threat['difficulty']}] {threat['threat']}")
            print(f"    Impact: {threat['impact']}")
            print(f"    Description: {threat['description']}")
            print(f"    Mitigation: {threat['mitigation']}")


if __name__ == "__main__":
    print_threat_assessment()
```

## Hands-on Exercises

### Exercise 1: AIS Vessel Tracking and Anomaly Detection

**Objective**: Set up an AIS receiver using RTL-SDR, decode vessel positions, and implement anomaly detection for suspicious maritime activity.

**Setup**: RTL-SDR dongle with a VHF antenna tuned to 162 MHz. Install rtl_ais and aisdecoder. A maritime location with vessel traffic nearby will produce better results.

**Tasks**:

1. Set up AIS reception:
   ```bash
   # Install AIS tools
   apt install rtl-ais aisdecoder

   # Start receiving AIS on both channels
   rtl_ais -l 161.975M -r 162.025M -g 40

   # In another terminal, start AIS decoder feeding NMEA to UDP
   aisdecoder -h 127.0.0.1 -p 10110 -a -f /dev/stdin
   ```

2. Capture 30 minutes of AIS traffic and build a vessel database:
   ```bash
   # Capture raw AIS data
   timeout 1800 rtl_fm -f 162000000 -M fm -s 48k -g 40 - | \
     aisdecoder -h 127.0.0.1 -p 10110 -a -f /dev/stdin

   # Log NMEA sentences
   netcat -u -l 10110 > ais_capture_$(date +%Y%m%d).nmea
   ```

3. Analyze the captured data for anomalies:
   - Vessels with invalid MMSI numbers
   - Speed/navigation status mismatches
   - Vessels near restricted areas
   - Vessels broadcasting conflicting identification data

**Deliverables**: AIS vessel database, anomaly detection report, list of vessels tracked with positions, written assessment of AIS security limitations.

### Exercise 2: ADS-B Aircraft Monitoring and Visualization

**Objective**: Set up an ADS-B receiver, decode aircraft positions in real-time, create a local aircraft tracking display, and assess the security implications of unauthenticated ADS-B data.

**Setup**: RTL-SDR dongle with a 1090 MHz antenna (a 13.8 cm wire works as a quarter-wave antenna). Install dump1090.

**Tasks**:

1. Set up dump1090 for real-time ADS-B reception:
   ```bash
   # Install dump1090
   apt install dump1090-mutability

   # Start with network output and web interface
   dump1090 --net --interactive --gain 40

   # Access web map at http://localhost:8080
   ```

2. Capture 1 hour of ADS-B data:
   ```bash
   # Start dump1090 with raw output logging
   dump1090 --net --interactive --gain 40 --write-json /tmp/adsb_data/

   # Alternatively, capture raw Mode-S messages
   timeout 3600 rtl_adsb -g 40 > adsb_raw_$(date +%Y%m%d).txt
   ```

3. Analyze the captured data:
   - Count unique aircraft (by ICAO hex code)
   - Identify aircraft types and operators
   - Map flight paths and identify patterns
   - Calculate maximum reception range

4. Write a security assessment of ADS-B covering:
   - Privacy implications of unencrypted tracking
   - Feasibility of ghost aircraft injection
   - Impact on military/government aircraft
   - Recommendations for ADS-B security improvements

**Deliverables**: Aircraft tracking data, flight path visualization, ADS-B security assessment report, reception statistics.

## References

1. **ITU-R M.1371** - Technical Characteristics for an Automatic Identification System Using Time Division Multiple Access in the VHF Maritime Mobile Band. The international standard defining AIS signal structure and protocol.

2. **RTCA DO-260B** - Minimum Operational Performance Standards for 1090 MHz Extended Squitter ADS-B and TIS-B. The standard defining ADS-B message formats and transmission requirements.

3. **NOAA KLM User's Guide** - Comprehensive documentation for NOAA polar-orbiting satellite APT signal format and decoding, https://www.ncdc.noaa.gov/

4. **GNU Radio APT Decoder** - Open-source GNURadio flowgraphs for NOAA APT signal decoding, available at https://github.com/

5. **dump1090 Documentation** - ADS-B decoder documentation and signal processing details, https://github.com/antirez/dump1090

6. **Libais** - Python AIS message decoder library supporting all message types, https://github.com/schwehr/libais

7. **SDR for Mariners** - AIS signal reception and vessel tracking resources for maritime security researchers.

8. **ICAO ADS-B Manual (Doc 9924)** - International Civil Aviation Organization guidance on ADS-B implementation and security considerations.

9. **"On Privacy and Security in AIS"** - Multiple academic papers analyzing AIS security vulnerabilities including spoofing, tracking, and jamming attacks.

10. **Gpredict** - Open-source satellite tracking and pass prediction software, essential for planning NOAA satellite reception sessions, https://gpredict.oz9aec.net/
