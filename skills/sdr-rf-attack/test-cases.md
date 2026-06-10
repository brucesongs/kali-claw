# SDR/RF Attack Test Cases

## TC-SRF-001: SDR Hardware Verification

- **Objective**: Verify SDR hardware (HackRF/RTL-SDR) is properly detected and functional
- **Severity**: HIGH
- **Prerequisites**: HackRF One or RTL-SDR v3 connected via USB, Kali Linux with sdr tools installed
- **Test Steps**:
  1. Run `hackrf_info` to verify HackRF detection
  2. Run `rtl_test -t` to verify RTL-SDR detection
  3. Check USB device listing with `lsusb`
  4. Run `hackrf_transfer --version` to verify driver version
- **Expected Result**: Device info displayed with serial number, firmware version; no errors
- **Remediation**: Update firmware with `hackrf_spiflash -H`, reload udev rules, check cable connection
- **Pass Criteria**: Device serial number and firmware version displayed without timeout or errors

## TC-SRF-002: Spectrum Scanning and Band Survey

- **Objective**: Perform comprehensive spectrum scan to identify active transmissions in target frequency bands
- **Severity**: MEDIUM
- **Prerequisites**: SDR hardware verified (TC-SRF-001), antenna connected, target frequency range known
- **Test Steps**:
  1. Run wideband scan: `rtl_power -f 300M:900M:10k -i 5 -e 300 wideband.csv`
  2. Analyze CSV output for peaks above noise floor
  3. Run focused scan on active frequencies with higher resolution
  4. Verify detected signals with gqrx waterfall display
- **Expected Result**: Active frequency bands identified with signal power levels; known transmitters visible in scan
- **Remediation**: Adjust antenna, increase gain, reduce scan bandwidth for better resolution
- **Pass Criteria**: At least 3 known active frequency bands detected with power levels above -60dB

## TC-SRF-003: GSM Network Interception

- **Objective**: Identify and capture GSM base station signals in the 900MHz band
- **Severity**: CRITICAL
- **Prerequisites**: SDR with 2MSPS+ capability, GSM900 band in range, gr-gsm installed
- **Test Steps**:
  1. Scan GSM900 channels: `grgsm_scanner -b GSM900 -g 40`
  2. Record BCCH of strongest cell: `grgsm_capture -f 935.4M -s 2000000 -g 40`
  3. Decode captured data: `grgsm_decode -c capture.cfile -t 0 -s 2000000`
  4. Extract cell identity (CID), LAC, MCC/MNC from decoded data
- **Expected Result**: GSM cells identified with ARFCN, CID, LAC, and MCC/MNC; BCCH successfully decoded
- **Remediation**: Increase gain, use external antenna, ensure correct band selection for region
- **Pass Criteria**: At least 1 GSM cell identified with valid CID, LAC, and MCC/MNC values

## TC-SRF-004: LTE Signal Analysis

- **Objective**: Detect and analyze LTE downlink signals including MIB/SIB extraction
- **Severity**: HIGH
- **Prerequisites**: SDR with 10MSPS+ capability, LTE band in coverage area
- **Test Steps**:
  1. Capture LTE signal: `hackrf_transfer -r lte.raw -f 1840M -s 10M -l 40 -g 30`
  2. Scan LTE band: `rtl_power -f 1800M:1900M:100k -i 5 -e 120 lte_band.csv`
  3. Analyze signal with inspectrum for PSS/SSS peaks
  4. Extract cell ID and bandwidth from detected signals
- **Expected Result**: LTE cells detected with PCI, bandwidth, and signal quality metrics
- **Remediation**: Use higher-gain antenna for weak signals, ensure sampling rate covers full LTE bandwidth
- **Pass Criteria**: LTE cell PCI detected and signal bandwidth identified correctly

## TC-SRF-005: RFID Signal Capture and Analysis

- **Objective**: Capture and analyze LF (125kHz) and HF (13.56MHz) RFID signals
- **Severity**: HIGH
- **Prerequisites**: SDR with appropriate antenna, RFID tags/readers in proximity
- **Test Steps**:
  1. Capture HF RFID signal: `hackrf_transfer -r hf_rfid.raw -f 13560000 -s 8000000 -l 40 -g 30`
  2. Analyze with urh: `urh -i hf_rfid.raw -f 13.56e6 -s 8e6`
  3. Auto-detect modulation: `urh --auto-detect -i hf_rfid.raw`
  4. Extract tag UID from decoded data
- **Expected Result**: RFID signal captured and modulation detected; tag UID extracted from decoded bits
- **Remediation**: Use dedicated RFID antenna, position antenna closer to tag, increase capture gain
- **Pass Criteria**: RFID modulation type correctly identified and tag data bits extracted

## TC-SRF-006: Keyfob Signal Capture and Replay

- **Objective**: Capture wireless keyfob signal and analyze for fixed code vs rolling code
- **Severity**: CRITICAL
- **Prerequisites**: Authorized test keyfob, SDR with appropriate frequency range, urh installed
- **Test Steps**:
  1. Capture multiple keyfob presses: `hackrf_transfer -r keyfob.raw -f 315M -s 8M -l 40 -g 30`
  2. Repeat capture 5 times for rolling code analysis
  3. Compare signals in urh: `urh --compare press1.raw press2.raw press3.raw`
  4. Analyze for repeating vs changing patterns in transmitted data
- **Expected Result**: Signal successfully captured; determination of fixed code (same bits each press) or rolling code (different bits each press)
- **Remediation**: Ensure clean capture environment, minimize interference, use band-pass filter
- **Pass Criteria**: Code type correctly classified (fixed vs rolling) based on bit comparison across multiple captures

## TC-SRF-007: Radio Protocol Reverse Engineering

- **Objective**: Reverse engineer unknown radio protocol using urh analysis workflow
- **Severity**: HIGH
- **Prerequisites**: Unknown radio device to analyze, SDR capture hardware, urh installed
- **Test Steps**:
  1. Record multiple transmissions: `urh -r -f 433.92e6 -s 2e6 -g 30 --device hackrf -d 3`
  2. Auto-detect modulation parameters: `urh --auto-detect -i recording.complex`
  3. Manual demodulation with adjusted parameters
  4. Compare multiple captures to identify protocol structure (preamble, sync, payload, checksum)
- **Expected Result**: Modulation type identified, bit rate determined, protocol fields mapped with preamble/sync/payload structure
- **Remediation**: Increase number of captures for better pattern matching, adjust center and noise thresholds
- **Pass Criteria**: Protocol structure documented with identified preamble, sync word, and payload boundaries

## TC-SRF-008: GNURadio Custom Flowgraph Development

- **Objective**: Develop and test custom GNURadio flowgraph for targeted signal processing
- **Severity**: MEDIUM
- **Prerequisites**: GNURadio installed, Python knowledge, target signal parameters known
- **Test Steps**:
  1. Design flowgraph with appropriate source block (osmosdr_source)
  2. Add signal processing blocks (filter, demodulator, decoder)
  3. Generate Python script from GRC file
  4. Execute and verify output matches expected signal characteristics
- **Expected Result**: Custom flowgraph successfully processes target signal and produces expected output
- **Remediation**: Verify block connections, adjust filter parameters, check sample rate compatibility
- **Pass Criteria**: Flowgraph executes without errors and produces correctly demodulated output

---

## Verification Checklist

- [ ] All SDR hardware properly detected and calibrated
- [ ] Spectrum scan covers target frequency ranges with adequate resolution
- [ ] Captured signals verified against known transmissions
- [ ] Protocol analysis results validated with multiple captures
- [ ] Custom flowgraphs tested with both recorded and live signals
- [ ] All tests documented with frequency, gain, and sample rate parameters
- [ ] Compliance with local radio regulations verified for all transmissions
