# SDR Signal Capture and Analysis Guide

## Introduction

Software Defined Radio (SDR) transforms radio frequency signals into digital data that can be analyzed, decoded, and manipulated using software. This capability has revolutionized wireless security testing by making it possible to examine protocols that were previously only accessible with expensive specialized equipment. This guide covers the fundamentals of SDR signal capture, processing, and analysis using common hardware like RTL-SDR and HackRF One.

SDR-based security testing requires understanding of radio fundamentals including frequency, modulation, sample rate, and signal-to-noise ratio. Each of these parameters affects what you can capture and how accurately you can decode the transmitted data. The two most common SDR platforms for security testing are the inexpensive RTL-SDR (receive-only, suitable for monitoring and analysis) and the HackRF One (capable of both transmit and receive, enabling replay attacks).

**Objectives**: Set up SDR hardware, capture and analyze RF signals, identify modulation schemes, and extract data from unknown protocols.

## Hardware Setup and Calibration

### RTL-SDR Setup

The RTL-SDR is an affordable USB dongle based on the Realtek RTL2832U chip that can receive signals from 24MHz to 1.7GHz. While limited to receive-only operation, it is excellent for signal reconnaissance and analysis.

```bash
# Verify RTL-SDR device is recognized
rtl_test -t

# Check USB device enumeration
lsusb | grep -i "realtek\|rtl"

# Test basic reception on a known frequency (FM radio)
rtl_fm -f 100.0e6 -M fm -s 200k -r 32k -l 320 -g 40 | aplay -r 32000 -f S16_LE

# Set specific gain value (higher gain = more sensitivity but more noise)
rtl_fm -f 162.400e6 -s 22050 -g 20 - | aplay -r 22050 -f S16_LE
```

### HackRF Setup

The HackRF One operates from 1MHz to 6GHz with both transmit and receive capability, making it the primary tool for active SDR testing including signal replay and injection.

```bash
# Verify HackRF device and firmware version
hackrf_info

# Check HackRF hardware capabilities
hackrf_transfer --version

# Set sample rate and gain parameters
hackrf_transfer -s 10000000 --amp -l 32 -g 30
```

## Spectrum Scanning and Monitoring

### Wideband Scanning

Before targeting specific frequencies, perform wideband spectrum scanning to identify active signals in the target environment. This reconnaissance step helps identify unexpected transmissions and maps the RF landscape.

```bash
# Scan FM broadcast band (88-108MHz)
rtl_power -f 88M:108M:100k -i 10 -e 60 fm_band.csv

# Scan 433MHz ISM band (common for IoT devices)
rtl_power -f 433M:434M:1k -i 1 -e 300 433mhz_band.csv

# Generate visual heatmap from scan data
python3 -m urh.heatmap fm_band.csv

# HackRF wideband sweep for 2.4GHz band
hackrf_sweep -f 2400:2500 -l 32 -g 30 -w 1000000
```

### Targeted Frequency Monitoring

```bash
# Continuous monitoring of a specific band with high resolution
rtl_power -f 300M:900M:10k -i 5 -e 3600 wideband_scan.csv

# Detect active transmissions in European ISM band
rtl_power -f 868M:869M:1k -i 1 -e 60 ism_868.csv
awk -F, '$6 > -50 {print $4,$5,$6}' ism_868.csv

# Monitor 315MHz band (common for automotive keyfobs in US)
rtl_power -f 314M:316M:1k -i 1 -e 300 keyfob_315.csv
```

## Signal Capture Techniques

### Raw IQ Capture

IQ (In-phase and Quadrature) data represents the raw complex signal samples captured by the SDR. This format preserves all signal information for later analysis and processing.

```bash
# Capture raw IQ data with HackRF at 433MHz
hackrf_transfer -r capture_433.raw -f 433920000 -s 8000000 -l 40 -g 30 -n 80000000

# Capture with RTL-SDR at lower sample rate
rtl_sdr -f 433920000 -s 2048000 -g 30 -n 20480000 capture_433.raw

# Capture specific signal for replay
hackrf_transfer -r doorbell.raw -f 315000000 -s 8000000 -l 40 -g 30 -n 800000000

# Continuous capture with timestamp for correlation
hackrf_transfer -r "capture_$(date +%s).raw" -f 315000000 -s 8000000 -l 40 -g 30
```

### Signal Conversion and Processing

```bash
# Convert raw IQ to WAV for audio analysis
sox -r 8000000 -e unsigned-integer -b 8 -c 2 capture_433.raw output.wav

# Frequency hopping capture (multiple channels)
for freq in 433.42M 433.62M 433.92M; do
  hackrf_transfer -r "capture_${freq}.raw" -f ${freq} -s 2000000 -l 40 -g 30 -n 20000000
done
```

## Signal Analysis with urh

The Universal Radio Hacker (urh) is the primary tool for analyzing and decoding unknown wireless protocols. It provides automated modulation detection, signal comparison, and protocol analysis capabilities.

```bash
# Record signal with urh CLI
urh -r -f 433.92e6 -s 2e6 -g 30 --device rtl_sdr -d 5 signal_recording.complex16s

# Analyze recorded signal
urh -i signal_recording.complex16s -f 433.92e6 -s 2e6

# Auto-detect modulation and protocol parameters
urh --auto-detect -i signal_recording.complex16s

# Decode with custom parameters
urh -i signal_recording.complex16s --demod OOK --bit-length 100 --sample-rate 2e6
```

## Hands-on Exercises

### Exercise 1: FM Radio Capture

Capture and demodulate an FM radio signal to verify SDR hardware is working correctly.

```bash
rtl_fm -f 100.1e6 -M fm -s 200k -r 32k -g 40 - | aplay -r 32000 -f S16_LE
```

### Exercise 2: ISM Band Survey

Perform a comprehensive survey of the 433MHz ISM band to identify all active transmitters in your environment.

```bash
rtl_power -f 433M:434M:100 -i 1 -e 60 ism_survey.csv
awk -F, '$6 > -50 {print $4,$5,$6}' ism_survey.csv | sort -u
```

### Exercise 3: Signal Replay

Capture a signal from a remote control device and replay it to verify the capture was successful.

```bash
hackrf_transfer -r remote.raw -f 433920000 -s 8000000 -l 40 -g 30
hackrf_transfer -t remote.raw -f 433920000 -s 8000000 -x 40
```

### Exercise 4: Protocol Analysis

Use urh to analyze an unknown signal, determine its modulation scheme, and decode the transmitted bits.

```bash
urh --auto-detect -i unknown_signal.complex16s
```

## References

- RTL-SDR documentation — https://www.rtl-sdr.com
- HackRF One documentation — https://greatscottgadgets.com/hackrf/
- Universal Radio Hacker — https://github.com/jopohl/urh
- GNU Radio project — https://www.gnuradio.org
- SDR security testing — Wireless Security Audit methodology
