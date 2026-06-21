# Licensed HF/VHF/UHF Radio Attack Test Cases

Test case templates for licensed HF/VHF/UHF radio band assessment. All test cases are receive-side unless explicitly marked as authorized research (Faraday cage required).

## TC-LF-001: SDR Hardware Verification for Licensed Bands

- **Objective**: Verify SDR hardware (HackRF/RTL-SDR/AirSpy HF+ Discovery/BladeRF) is properly detected and functional for licensed band reception
- **Severity**: HIGH
- **Prerequisites**: One or more of: HackRF One, RTL-SDR v3, AirSpy HF+ Discovery, BladeRF 2.0 micro, PlutoSDR connected via USB with appropriate antennas
- **Test Steps**:
  1. Verify HackRF One detection: `hackrf_info`
  2. Verify RTL-SDR v3 detection and tuner type: `rtl_test -t`
  3. Verify AirSpy HF+ Discovery detection: `airspy_rx --help 2>&1 | head -5`
  4. Verify BladeRF 2.0 micro detection: `bladerf-cli --probe`
  5. List all SDR devices: `lsusb | grep -i "realtek\|hackrf\|nuand\|airspy\|analog"`
  6. Verify installed decoders: `dump1090 --version; multimon-ng --version; dumpvdl2 --version`
- **Expected Result**: All connected SDR devices detected with serial numbers and firmware versions; decoder tools report versions without error
- **Remediation**: Update firmware with vendor-specific tools, reload udev rules (`sudo udevadm control --reload-rules`), verify cable connections, install missing decoders from source
- **Pass Criteria**: At least one SDR device detected; all primary decoders (dump1090, multimon-ng, dumpvdl2) report version strings without errors

## TC-LF-002: ADS-B Aircraft Tracking (1090 MHz)

- **Objective**: Receive and decode ADS-B Mode S extended squitters from aircraft at 1090 MHz
- **Severity**: HIGH
- **Prerequisites**: SDR hardware verified (TC-LF-001), RTL-SDR v3 or better with 1090 MHz antenna, dump1090-mutability or readsb installed, line-of-sight to aircraft traffic (within 300+ nm of an airport or flight path)
- **Test Steps**:
  1. Connect 1090 MHz antenna to RTL-SDR v3
  2. Start dump1090-mutability: `dump1090 --net --gain 40 --ppm 0 --aggressive --interactive --quiet &`
  3. Verify reception: `nc localhost 30003 | head -20`
  4. Check web GUI at http://localhost:8080 for live aircraft map
  5. Capture raw I/Q for offline analysis: `rtl_sdr -f 1090000000 -s 2000000 -g 40 -n 20000000 adsb_sample.raw`
  6. Decode from capture: `dump1090 --ifile adsb_sample.raw --fix --aggressive`
  7. Extract aircraft list with ICAO24 addresses, callsigns, and positions
- **Expected Result**: At least 5 aircraft decoded within 10 minutes with valid ICAO24 addresses (cross-reference with FAA aircraft registry), callsigns, and position reports
- **Remediation**: Adjust antenna position for better sky view, increase gain, calibrate PPM offset using `kal -g 40 -e`, verify line-of-sight to air traffic
- **Pass Criteria**: At least 3 unique aircraft ICAO24 addresses decoded with valid callsigns and position reports within a 10-minute capture window

## TC-LF-003: AIS Maritime Vessel Tracking (161.975 / 162.025 MHz)

- **Objective**: Receive and decode AIS Class A and Class B position reports from maritime vessels
- **Severity**: HIGH
- **Prerequisites**: SDR hardware verified, VHF marine antenna (161.975/162.025 MHz), AIS-catcher or rtl_ais installed, location within VHF range of vessel traffic (port, coastal, or river)
- **Test Steps**:
  1. Connect VHF marine antenna to RTL-SDR v3
  2. Start AIS-catcher: `AIS-catcher -u 12345 -v -T -g 40 &`
  3. Verify NMEA-0183 output: `nc -u -l 12345 | head -20`
  4. Capture raw AIS I/Q: `rtl_sdr -f 161975000 -s 250000 -g 40 -n 2500000 ais_sample.raw`
  5. Decode from capture: `AIS-catcher --input ais_sample.raw --output ais_decoded.json`
  6. Extract vessel list with MMSI, name, position, speed, heading
  7. Cross-reference MMSI prefixes with ITU country codes
- **Expected Result**: At least 3 vessels decoded within 30 minutes with valid 9-digit MMSIs, names (where broadcast), positions, and course/speed data
- **Remediation**: Reposition antenna for better water view, use a tuned VHF marine antenna (not generic discone), verify AIS-catcher version supports multi-channel reception
- **Pass Criteria**: At least 2 unique vessel MMSIs decoded with position reports; at least one with ship name in static data message

## TC-LF-004: ACARS Airline Communications (131.550 MHz)

- **Objective**: Receive and decode ACARS messages from aircraft airline operational communications
- **Severity**: HIGH
- **Prerequisites**: SDR hardware verified, VHF air band antenna (118-137 MHz), ACARSDeco or acarsdec installed, location near commercial aircraft traffic (airport-adjacent or under a flight corridor)
- **Test Steps**:
  1. Connect VHF air band antenna to RTL-SDR v3
  2. Start ACARSDeco: `acarsdeco -r 0:131550000 -g 40 --silence-level 5 &`
  3. Verify web GUI at http://localhost:8080 for live ACARS messages
  4. Capture raw ACARS I/Q: `rtl_sdr -f 131550000 -s 250000 -g 40 -n 25000000 acars_sample.raw`
  5. Decode from capture with acarsdec
  6. Extract message list with tail numbers, flight IDs, message content
  7. Identify message types: airline operational (AOC), ATC uplinks, CPDLC
- **Expected Result**: At least 10 ACARS messages decoded within 30 minutes with valid tail numbers, flight identifiers, and message content (some may be readable, others may be encoded AOC protocol)
- **Remediation**: Verify antenna covers 131.550 MHz with reasonable VSWR, try alternate ACARS channels (131.725, 131.525 US alternates), increase capture duration during peak air traffic hours
- **Pass Criteria**: At least 5 ACARS messages decoded with valid aircraft tail numbers; at least one message containing readable AOC content

## TC-LF-005: VDL Mode 2 (136.975 MHz)

- **Objective**: Receive and decode VDL Mode 2 digital aircraft data link messages
- **Severity**: MEDIUM
- **Prerequisites**: SDR hardware verified, VHF air band antenna, dumpvdl2 built from source, location near aircraft traffic
- **Test Steps**:
  1. Verify dumpvdl2 installation: `dumpvdl2 --version`
  2. Start dumpvdl2: `dumpvdl2 --gain 40 --corrupted-messages --output decoded:text:file:stdout &`
  3. Capture raw VDL Mode 2 I/Q: `rtl_sdr -f 136975000 -s 250000 -g 40 -n 25000000 vdlm2_sample.raw`
  4. Decode from capture: `dumpvdl2 --ifile vdlm2_sample.raw --output decoded:text:file:stdout`
  5. Extract VDL Mode 2 messages with aircraft addresses, ground station, and content
  6. Identify AVLC frame types: I (information), S (supervisory), U (unnumbered)
- **Expected Result**: At least 5 VDL Mode 2 messages decoded within 30 minutes with valid aircraft ICAO24 addresses and ground station identifiers
- **Remediation**: VDL Mode 2 traffic varies by region; check if your location is within range of a VDL Mode 2 ground station, ensure SDR gain is optimized for D8PSK demodulation
- **Pass Criteria**: At least 2 VDL Mode 2 messages decoded with valid source/destination addresses and message content; at least one containing ACARS-over-VDL (AOV) payload

## TC-LF-006: HFDL Oceanic Aircraft Comms (HF Bands)

- **Objective**: Receive and decode HFDL messages from oceanic aircraft communications
- **Severity**: MEDIUM
- **Prerequisites**: AirSpy HF+ Discovery (preferred for HF) or RTL-SDR v3 in direct sampling mode, HF antenna (magnetic loop or long wire), dumphfdl built from source, location with propagation paths to HFDL ground stations (US, Europe, or Asia)
- **Test Steps**:
  1. Connect HF antenna to AirSpy HF+ Discovery
  2. Start dumphfdl on common HFDL frequencies: `dumphfdl --gain 40 --output decoded:text:file:stdout 2941000 5455000 8927000 11306000 15025000 17922000 &`
  3. Monitor for activity over 30-60 minutes (HFDL traffic is sparse)
  4. Capture raw I/Q on an active frequency: `airspy_rx -f 8927 -r hfdl_sample.air -g 12 -b 192000 -n 1920000`
  5. Decode from capture: `dumphfdl --ifile hfdl_sample.air --output decoded:text:file:stdout`
  6. Identify ground stations (ARINC, SITA) and aircraft using HFDL
- **Expected Result**: At least 1 HFDL message decoded within 60 minutes with ground station ID, aircraft identifier, and message content (HFDL traffic is sparse, patience required)
- **Remediation**: HFDL propagation varies by time of day and solar conditions; monitor multiple frequencies, try different times (day vs night propagation), use a proper HF antenna (not VHF antenna adapted)
- **Pass Criteria**: At least 1 HFDL message decoded with valid ground station identifier and aircraft address; alternatively, document signal presence even if not fully decodable

## TC-LF-007: POCSAG Pager Decoding

- **Objective**: Receive and decode POCSAG pager messages from a local pager fleet
- **Severity**: HIGH (privacy implications)
- **Prerequisites**: SDR hardware verified, antenna appropriate for target pager band (138-174 MHz, 440-470 MHz, or 929-932 MHz), multimon-ng installed, location within range of a pager fleet (hospital, public safety, utility)
- **Test Steps**:
  1. Survey pager band: `rtl_power -f 929M:932M:10k -i 2 -e 300 pager_900.csv`
  2. Identify active pager frequency from survey
  3. Start multimon-ng on active frequency: `rtl_fm -f 929.5e6 -s 22050 -g 40 - | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX -`
  4. Capture raw I/Q: `rtl_sdr -f 929500000 -s 250000 -g 40 -n 25000000 pager_sample.raw`
  5. Convert to WAV: `sox -t raw -r 250000 -e signed-integer -b 16 -c 2 pager_sample.raw -r 22050 -c 1 pager_sample.wav`
  6. Decode from WAV: `multimon-ng -t wav -a POCSAG1200 -a FLEX pager_sample.wav`
  7. Extract pager messages with capcodes (pager IDs) and content
  8. Audit content for PHI patterns (dates, names, MRN numbers, department codes)
- **Expected Result**: At least 20 pager messages decoded within 30 minutes with valid capcodes and message content
- **Remediation**: Survey other pager bands if 900 MHz is inactive, try 138-174 MHz (VHF high) or 440-470 MHz (UHF), increase antenna gain, position antenna outside building for better reception
- **Pass Criteria**: At least 10 POCSAG messages decoded with valid capcodes; content audit identifies any PHI exposure patterns

## TC-LF-008: FLEX Pager Decoding

- **Objective**: Receive and decode FLEX protocol pager messages (more sophisticated than POCSAG)
- **Severity**: HIGH
- **Prerequisites**: SDR hardware verified, antenna for 929-932 MHz (or 161-166 MHz depending on region), multimon-ng with FLEX support, location within range of a FLEX pager fleet
- **Test Steps**:
  1. Verify multimon-ng FLEX support: `multimon-ng --help 2>&1 | grep FLEX`
  2. Survey FLEX frequencies (typically 929-932 MHz in US): `rtl_power -f 929M:932M:5k -i 2 -e 300 flex_band.csv`
  3. Start FLEX decoding: `rtl_fm -f 929.5e6 -s 22050 -g 40 - | multimon-ng -t raw -a FLEX -`
  4. Capture raw I/Q for offline analysis
  5. Identify FLEX sync phases (A, B, C, D) and frame structure
  6. Decode capcodes and message content
- **Expected Result**: At least 5 FLEX messages decoded within 30 minutes with valid capcodes and content
- **Remediation**: FLEX signals are typically at higher power than POCSAG but harder to decode; verify multimon-ng was built with FLEX_SUPPORT=ON, try adjusting rtl_fm gain and squelch
- **Pass Criteria**: At least 3 FLEX messages decoded with valid capcodes; documented which FLEX speed (1600/3200/6400 bps) is in use at the target site

## TC-LF-009: APRS Amateur Radio Position Reporting

- **Objective**: Receive and decode APRS packets from amateur radio operators
- **Severity**: MEDIUM
- **Prerequisites**: SDR hardware verified, 2m amateur band antenna (144 MHz), multimon-ng or direwolf installed, location within range of amateur radio APRS activity (urban area with active hams)
- **Test Steps**:
  1. Connect 2m antenna to RTL-SDR v3
  2. Decode APRS at US frequency (144.39 MHz): `rtl_fm -f 144.39e6 -s 22050 -g 40 - | multimon-ng -t raw -a AFSK1200 -`
  3. Alternative with direwolf (full TNC): `rtl_fm -f 144.39e6 -s 48000 -g 40 - | direwolf -r 48000 -b 16 -n -`
  4. Capture raw I/Q: `rtl_sdr -f 144390000 -s 250000 -g 40 -n 2500000 aprs_sample.raw`
  5. Decode from capture
  6. Extract APRS station data: callsigns, positions, status, messages
  7. Identify packet types: position, status, message, weather, telemetry
- **Expected Result**: At least 5 APRS packets decoded within 30 minutes with valid amateur callsigns and position reports
- **Remediation**: APRS activity varies by location; try European frequency (144.64 MHz) if in EU, ensure antenna is resonant at 144 MHz (not a generic discone), check for local APRS digipeaters
- **Pass Criteria**: At least 3 unique amateur callsigns decoded with position reports; at least one valid lat/lon position extracted

## TC-LF-010: NDB Aviation Beacon Tracking

- **Objective**: Receive and identify aviation Non-Directional Beacons (NDBs) via Morse code identifiers
- **Severity**: MEDIUM
- **Prerequisites**: AirSpy HF+ Discovery (preferred) or RTL-SDR v3 in direct sampling mode, LF/MF antenna (loop or long wire), GQRX or similar SDR receiver, location within range of NDBs (typically 100-500 nm)
- **Test Steps**:
  1. Connect LF/MF antenna to AirSpy HF+ Discovery
  2. Scan NDB band: `rtl_power -f 190000:535000:1000 -i 5 -e 60 -g 40 ndb_scan.csv` (or use AirSpy for better HF performance)
  3. Identify peaks in scan output
  4. Tune to candidate frequency in GQRX with CW mode (narrow bandwidth 100-200 Hz)
  5. Listen for Morse code identifier (typically 2-3 letters at 10-20 WPM)
  6. Decode Morse identifier manually or with multimon-ng CW mode
  7. Cross-reference identifier with FAA NDB database
- **Expected Result**: At least 2 NDB signals identified with decoded Morse identifiers matching FAA database entries
- **Remediation**: Use a proper LF/MF antenna (magnetic loop preferred), scan during evening hours when LF/MF propagation is better, position antenna away from power lines (man-made noise at LF/MF)
- **Pass Criteria**: At least 1 NDB identified with Morse code identifier matching a known NDB in the FAA database (identifier, frequency, location)

## TC-LF-011: Weather Fax Reception (HF)

- **Objective**: Receive and decode weather fax images broadcast by meteorological services
- **Severity**: LOW
- **Prerequisites**: AirSpy HF+ Discovery or RTL-SDR with HF capability, HF antenna, fldigi or similar weather fax decoder, location with HF propagation to NOAA/DWD/JMA transmitters
- **Test Steps**:
  1. Connect HF antenna to AirSpy HF+ Discovery
  2. Identify active weather fax frequency from NOAA schedule (e.g., 9.110 MHz for Pt Reyes CA)
  3. Capture audio from GQRX in USB mode with 2.5 kHz bandwidth
  4. Launch fldigi with WEFAX mode: `fldigi --op-mode WEFAX-576 &`
  5. Pipe captured audio to fldigi
  6. Wait for sync and image reception (typical image takes 10-15 minutes)
  7. Save decoded image
- **Expected Result**: At least partial weather fax image decoded within 30 minutes showing recognizable weather features (coastlines, pressure systems)
- **Remediation**: Verify HF propagation path to target transmitter (check space weather conditions), try different frequencies based on time of day, ensure fldigi is in correct WEFAX mode (IOC 576 or 288)
- **Pass Criteria**: At least partial weather fax image decoded with recognizable geographic features; documented transmitter source and frequency

## TC-LF-012: DSC Maritime Distress Decode

- **Objective**: Receive and decode DSC (Digital Selective Calling) messages on VHF Channel 70
- **Severity**: MEDIUM
- **Prerequisites**: SDR hardware verified, VHF marine antenna, multimon-ng or dedicated DSC decoder, location within range of maritime DSC traffic (port or coastal area with active vessels)
- **Test Steps**:
  1. Connect VHF marine antenna to RTL-SDR v3
  2. Capture Channel 70 I/Q: `rtl_sdr -f 156525000 -s 250000 -g 40 -n 25000000 dsc_sample.raw`
  3. Attempt decode with multimon-ng: `multimon-ng -t wav -a DTMF dsc_sample.wav` (limited DSC support)
  4. Alternatively, monitor Channel 70 in GQRX for DSC signal presence
  5. Document DSC protocol structure (GFSK 1200 bps, ITU-R M.493)
  6. If dedicated DSC decoder available, decode message type (routine, urgency, distress)
  7. Cross-reference MMSI in DSC messages with vessel tracking
- **Expected Result**: At least 1 DSC signal detected within 60 minutes (DSC traffic is sparse; routine calls are common, distress calls are rare)
- **Remediation**: DSC decoders are less mature than AIS decoders; document signal presence even if full decode fails, try monitoring MF 2187.5 kHz with HF-capable SDR for additional DSC traffic
- **Pass Criteria**: At least 1 DSC signal detected on Channel 70 with documented signal characteristics (frequency, modulation, frame structure); if decoded, message type and MMSI identified
