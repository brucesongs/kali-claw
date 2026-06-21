# Licensed HF/VHF/UHF Radio Attack Playbook

A comprehensive playbook for assessing licensed HF/VHF/UHF radio services (aviation, maritime, paging, amateur). This playbook covers hardware selection, decoding matrix, real-world research context, antenna design basics, legal/ethical considerations, and lab setup.

## Introduction

Licensed radio services in the HF/VHF/UHF spectrum (3 kHz - 1500 MHz) are the backbone of aviation, maritime, and public safety communications. Unlike unlicensed ISM devices (covered in `sdr-rf-attack`), these services operate under strict licensing regimes (FCC Part 87 aviation, Part 80 maritime, Part 97 amateur in the US) and many are safety-of-life services where interference is a federal crime.

The defining characteristic of licensed band assessment is **asymmetry**: receivers can map aircraft, vessels, pagers, and tactical voice traffic without transmitting a single photon, while any transmission requires explicit licensing and is otherwise illegal. This playbook emphasizes receive-side intelligence, OPSEC, and protocol-security research -- the dominant pattern in licensed band work -- with transmit-side attacks (spoofing, jamming) documented as research context only.

This skill targets licensed services **above Sub-GHz ISM** (433/868/915 MHz keyfobs and IoT, in `sdr-rf-attack`) and **below cellular operator bands** (700/850/1800/2600/3500 MHz 5G/LTE, in `5g-telecom-attack`). The frequencies in scope: ADS-B at 1090 MHz, AIS at 161.975/162.025 MHz, ACARS at 131.550 MHz, VDL Mode 2 at 136.975 MHz, HFDL across multiple HF bands, POCSAG/FLEX pagers, APRS at 144.39 MHz (US) / 144.64 MHz (EU), NDB at 190-535 kHz, weather fax on HF, DSC on Channel 70 (156.525 MHz), ATC voice (118-137 MHz AM), maritime VHF voice (Ch 16 at 156.8 MHz), and MLAT/TIS-B/UAT at 978 MHz. Inmarsat and Iridium L-band (1525-1660 MHz) are covered briefly for context as the upper edge of this spectrum.

**Objectives**: Master licensed band SDR hardware selection for each target service, implement aircraft/vessel/pager tracking and anomaly detection, understand the protocol security posture of ADS-B/AIS/ACARS/POCSAG, design appropriate antennas for HF/VHF/UHF bands, navigate the legal and ethical framework for licensed band assessment, and build a lab capable of supporting engagement work.

## Part 1: SDR Hardware Tier Table

Different licensed band assessment scenarios require different hardware. The following table categorizes SDR platforms by capability tier.

### Tier 1: Receive-Only Low-Cost (RX-only, <$200)

| Platform | Frequency Range | Bandwidth | Sample Rate | Cost | Best Licensed-Band Use Case |
|----------|----------------|-----------|-------------|------|-----------------------------|
| **RTL-SDR v3** | 24-1766 MHz (HF via Q-branch direct sampling) | 2.4 MHz | 2.4 MSPS | $30 | ADS-B (1090 MHz), AIS, POCSAG, ACARS, ATC voice, APRS -- 90% of receive-only work |
| **AirSpy HF+ Discovery** | 9 kHz - 31 MHz (HF), 60-260 MHz (VHF) | 768 kHz (HF) | 768 kSPS | $170 | HF bands: NDB, weather fax, HFDL, MF/HF DSC, HF amateur |
| **AirSpy Mini** | 24-1800 MHz | 6 MHz | 6 MSPS | $100 | Wideband VHF/UHF receive with high dynamic range |
| **SDRplay RSPdx** | 1 kHz - 2 GHz | 10 MHz | 10 MSPS | $200 | Wideband HF/VHF/UHF from one device, with built-in notch filters |

**Selection guideline for RX-only**: An RTL-SDR v3 ($30) covers 90% of receive-only licensed band work. Add an AirSpy HF+ Discovery ($170) for serious HF work (NDB, weather fax, HFDL). These two devices together cost $200 and cover all licensed bands from 9 kHz to 1766 MHz.

### Tier 2: TX/RX Capable (Half-Duplex, $200-$500)

| Platform | Frequency Range | Bandwidth | Sample Rate | Cost | Best Licensed-Band Use Case |
|----------|----------------|-----------|-------------|------|-----------------------------|
| **HackRF One** | 1 MHz - 6000 MHz | 20 MHz | 20 MSPS | $330 | Authorized TX research in Faraday cage: ADS-B/AIS replay, protocol testing |
| **PlutoSDR (ADALM-PLUTO)** | 325-3800 MHz (default), 70-6000 MHz (mod) | 20 MHz | 20 MSPS | $200 | Custom GNU Radio decoders, ADS-B/UAT research, learning |
| **LimeSDR USB** | 100 kHz - 3.8 GHz | 30 MHz | 30 MSPS | $300 | Cost-effective TX/RX, protocol emulation |

**Selection guideline for TX research**: HackRF One is the standard for authorized TX research (replay, spoofing in Faraday cage). PlutoSDR is preferred for custom GNU Radio decoders due to its tight Analog Devices integration.

### Tier 3: Full-Duplex / Professional ($500+)

| Platform | Frequency Range | Bandwidth | Sample Rate | Cost | Best Licensed-Band Use Case |
|----------|----------------|-----------|-------------|------|-----------------------------|
| **BladeRF 2.0 micro a4** | 47 MHz - 6000 MHz | 56 MHz | 61 MSPS | $480 | Full-duplex protocol emulation (VDL Mode 2, VHF voice relay research) |
| **USRP B210** | 70 MHz - 6000 MHz | 56 MHz | 61 MSPS | $1200 | Professional engagements, MIMO, highest fidelity |
| **Ettus USRP X310** | DC - 6 GHz | 100 MHz | 200 MSPS | $3000+ | Research-grade, multi-channel synchronous capture |

**Selection guideline for professional work**: BladeRF 2.0 micro a4 provides full-duplex capability at a reasonable price. USRP B210 is the professional standard for engagements requiring highest fidelity and MIMO.

## Part 2: Licensed Band Decoding Matrix

The matrix below maps each licensed service to the appropriate decoder tool and hardware recommendation. This is the quick-reference for engagement planning.

| Licensed Service | Frequency | Modulation | Decoder Tool | RX Hardware | Antenna |
|------------------|-----------|------------|--------------|-------------|---------|
| **ADS-B (Mode S Long Squitter)** | 1090 MHz | PPM | dump1090-mutability, readsb | RTL-SDR v3 | 1090 MHz collinear (8-element) |
| **UAT (ADS-B)** | 978 MHz | GFSK | dump978 | RTL-SDR v3 | 978 MHz collinear or discone |
| **AIS Class A/B** | 161.975 / 162.025 MHz | GMSK 9600 bps | AIS-catcher, rtl_ais | RTL-SDR v3 | VHF marine (J-pole or whip) |
| **ACARS** | 131.550 MHz (primary) | AM MSK 2400 bps | ACARSDeco, acarsdec | RTL-SDR v3 | VHF air band discone |
| **VDL Mode 2** | 136.975 MHz | D8PSK 31500 sym/s | dumpvdl2 | RTL-SDR v3 | VHF air band discone |
| **HFDL** | 2.941, 5.455, 8.927, 11.306, 15.025, 17.922 MHz | DPSK 300/600/1200/1800 bps | dumphfdl | AirSpy HF+ Discovery | HF wire dipole or magnetic loop |
| **POCSAG** | 138-174, 440-470, 929-932 MHz | 2-FSK 512/1200/2400 bps | multimon-ng | RTL-SDR v3 | Band-appropriate vertical |
| **FLEX** | 929-932, 161-166 MHz | 4-FSK 1600/3200/6400 bps | multimon-ng (FLEX_SUPPORT=ON) | RTL-SDR v3 | Band-appropriate vertical |
| **APRS** | 144.39 MHz (US), 144.64 MHz (EU) | AFSK 1200 bps Bell 202 | multimon-ng, direwolf | RTL-SDR v3 | 2m amateur vertical |
| **NDB** | 190-535 kHz, 1750 kHz | AM MCW | GQRX (CW mode), GNURadio | AirSpy HF+ Discovery | LF/MF magnetic loop or long wire |
| **Weather Fax** | HF (e.g., 4.625, 8.074, 9.110 MHz) | FM subcarrier on AM | fldigi (WEFAX mode) | AirSpy HF+ Discovery | HF wire dipole |
| **DSC VHF** | 156.525 MHz (Ch 70) | GFSK 1200 bps | multimon-ng (limited), rtl-dsc | RTL-SDR v3 | VHF marine |
| **DSC MF/HF** | 2187.5, 4207.5, 6312, 8414.5, 12577, 16804.5 kHz | GFSK 1200 bps | rtl-dsc | AirSpy HF+ Discovery | HF wire dipole |
| **ATC Voice** | 118-137 MHz AM (25 kHz or 8.33 kHz spacing) | AM | GQRX, SDR#, rtl_fm | RTL-SDR v3 | VHF air band discone |
| **Maritime VHF Voice** | 156-174 MHz (Ch 16 = 156.8 MHz) FM | NBFM | GQRX, SDR#, rtl_fm | RTL-SDR v3 | VHF marine |
| **MLAT** | 1090 MHz (cooperative) | PPM | dump1090-mutability + peers | RTL-SDR v3 | 1090 MHz collinear |
| **TIS-B** | 1090 MHz, 978 MHz | PPM/GFSK | dump1090, dump978 | RTL-SDR v3 | Discone or dedicated |
| **Inmarsat STD-C** | 1530-1545 MHz | TDMA 600 bps | Research tools | AirSpy R2 / HackRF | L-band patch + LNA |
| **Iridium** | 1616-1626.5 MHz | TDMA QPSK | iridium-toolkit | HackRF / AirSpy | L-band patch + LNA |

## Part 3: Real-World Research and Documented Vulnerabilities

### ADS-B Spoofing Research

**Povolny & Wang (2012): "On the Security of the ADS-B Protocol"**

Povolny and Wang published seminal research demonstrating that ADS-B has no cryptographic authentication, allowing trivial spoofing with software-defined radio. Key findings:

- ADS-B messages are broadcast in clear text with no encryption or authentication
- Any SDR transmitter (USRP, HackRF) can broadcast valid-looking ADS-B messages
- The ICAO24 address is a static identifier with no cryptographic binding to the aircraft
- Receivers cannot distinguish between legitimate and spoofed transmissions
- Demonstrated attacks: ghost aircraft injection, trajectory manipulation, aircraft disappearance

**Costin & Francillon (2012): "Ghost in the Air (Rerouted)"**

Costin and Francillon extended ADS-B vulnerability research using low-cost RTL-SDR hardware (originally a $20 TV tuner dongle). Key contributions:

- Demonstrated ADS-B reception and analysis using RTL-SDR (radically lowered cost of ADS-B research)
- Documented the lack of security in the ADS-B protocol stack
- Showed that ghost aircraft could be created by replaying captured messages
- Highlighted the absence of authentication in the next-generation air traffic surveillance system

**Implications for engagement work**: ADS-B reception is universally legal (it is unencrypted broadcast). ADS-B spoofing research must be confined to Faraday cages. Engagement deliverables can document the protocol's inherent insecurity and recommend anomaly-detection mitigations (multilateration cross-validation, behavior-based detection).

### Trend Micro Maritime AIS Research (2019-2020)

Trend Micro's Forward-Looking Threat Research team documented extensive AIS spoofing in contested waters:

- **South China Sea**: Circular formations of spoofed vessels around disputed islands
- **Black Sea**: Vessels appearing inland (impossible positions)
- **Oil terminals**: Thousands of fake vessels concentrated at strategic facilities
- **Military vessel spoofing**: AIS positions broadcast from real naval vessels at incorrect locations

**Documented spoofing patterns**:

1. **Circular formations**: Multiple vessels arranged in a perfect circle (physically impossible)
2. **Vessels on land**: AIS positions reported inland (coastline crossing)
3. **Mass spoofing**: Hundreds of vessels with the same position
4. **Path manipulation**: Vessels appearing to take impossible paths (through other vessels)
5. **Identity spoofing**: Vessels using the MMSI of another (often military) vessel

**Implications for engagement work**: AIS reception is legal and useful for vessel traffic characterization. Engagement deliverables should document the protocol's lack of authentication and recommend cross-validation with radar, visual, and satellite AIS sources.

### DEF CON Talks on ACARS and POCSAG

**DEF CON 18 (Andrea Barisani & Matteo Mancini): "Pager networks: intercepting messages nationwide"**

Barisani and Mancini demonstrated nationwide coverage of US pager networks from a single rooftop in Los Angeles. Key findings:

- Hospital pagers routinely transmit patient PHI (names, room numbers, physician names, diagnoses)
- Public safety pagers transmit dispatch codes, addresses, and operational data
- Utility pagers transmit infrastructure alerts and dispatch
- Pager coverage often spans hundreds of miles (high-power transmitters)
- A single SDR receiver can capture millions of pager messages per day

**Implications for HIPAA assessments**: Hospital pager fleet audits are a high-value engagement deliverable. Decoded PHI exposure rates (typically 10-50% of pager messages in hospital fleets) provide concrete remediation recommendations: migrate to encrypted paging or secure mobile messaging.

**DEF CON 22 (Phaedrus): "Plane Spotters Guide to Hacking Aircraft"**

Phaedrus documented ACARS and VDL Mode 2 vulnerabilities from an attacker perspective:

- ACARS messages are unencrypted and reveal aircraft intent, fuel state, crew comms
- VDL Mode 2 inherits ACARS security weaknesses despite being newer
- Aircraft data link messages can be used for OSINT on airline operations
- Combined with ADS-B tracking, ACARS provides a complete operational picture

**Implications for aviation-adjacent facility assessments**: Decoding ACARS from a rooftop receiver reveals airline operational communications for any flight path within VHF range (typically 200+ nm at altitude).

### Costin, Francillon, et al. (2012+) - Continued Aircraft Protocol Research

Subsequent research extended to Mode S, ACARS over VDL Mode 2, and the upcoming LDACS (L-band Digital Aeronautical Communications System):

- Mode S interrogations are also unauthenticated
- VDL Mode 2 carries the same ACARS payload with no encryption
- LDACS (future aviation data link) proposes cryptographic protection but is not yet deployed

## Part 4: Antenna Design Basics

### 1090 MHz ADS-B Antenna

The most common ADS-B antenna design is the **8-element coaxial collinear** (often called a "spider" or "coco"). This design provides ~6-8 dBi gain omnidirectionally and is easy to build.

**Element length calculation**:

```
Wavelength at 1090 MHz = c / f = 299792458 / 1090e6 = 0.275 m = 275 mm
Half-wave element = 275 / 2 = 137.5 mm
Quarter-wave element = 275 / 4 = 68.8 mm
Coax element with velocity factor 0.85 (RG6) = 137.5 * 0.85 = 117 mm
```

**Construction**:

1. Cut 8 lengths of RG6 coax, each 117 mm (for half-wave collinear segments)
2. Stack segments vertically, alternating shield and center conductor connections
3. Add quarter-wave whip at top (69 mm of wire)
4. Mount in PVC pipe for weatherproofing
5. Connect to RTL-SDR with F-connector

**Alternative commercial options**: FlightAware Pro Stick Plus (RTL-SDR + LNA + 1090 MHz filter, $35), antenna-only options from RadarBox or FlightAware.

### VHF Marine Antenna (AIS, Maritime VHF)

For AIS (161.975/162.025 MHz) and maritime VHF voice (156-174 MHz), a simple **J-pole** or **quarter-wave ground plane** antenna is effective.

**J-pole construction**:

```
Wavelength at 162 MHz = 299792458 / 162e6 = 1.85 m
Half-wave radiator = 925 mm
Quarter-wave matching stub = 463 mm
```

**Alternative**: A 1/4 wave whip with ground plane radials (4-8 radials at 45 degrees down) at 463 mm each provides omnidirectional reception.

**Commercial options**: Shakespeare, Digital Antenna, and other marine antenna manufacturers sell tuned VHF marine antennas from $30-$100.

### VHF Air Band Discone (ATC Voice, ACARS, VDL Mode 2)

A discone antenna covers a very wide frequency range (typically 25-1300 MHz) with low gain. Ideal for receiving multiple licensed services with one antenna.

**Typical discone specs**: 0-2 dBi gain, omnidirectional, VSWR < 2:1 across the rated band.

**Commercial options**: Diamond D130J ($90), Comet DS300S ($100), Watson WSD-882 ($70).

**Limitation**: Discones are low-gain. For fringe reception, a dedicated vertical (e.g., ground plane for 131.550 MHz) provides better performance than a discone.

### HF Antennas (NDB, Weather Fax, HFDL, MF/HF DSC)

HF antennas are physically large (due to long wavelengths) and require special consideration.

**Magnetic loop** (preferred for HF receiving):

- 1-3 meter diameter loop of wire or tubing
- Directional null for noise rejection
- Tunable across HF bands
- Commercial options: Wellbrook ALA1530 ($250), Pixel Technologies RF Pro 1B ($450)

**Long wire / random wire**:

- 30-100 feet of wire, ideally outdoors and away from noise sources
- Use with 9:1 unun (unbalanced-to-unbalanced transformer)
- Low cost, moderate performance

**Active antenna (Mini-Whip style)**:

- Small PC-board antenna (PA0RDT Mini-Whip)
- Active amplifier provides good HF reception in small form factor
- Mount outside, away from local noise sources

**Critical HF consideration**: Man-made noise (switching power supplies, LED lights, PLC devices) dominates the HF noise floor in urban environments. Magnetic loops with their directional nulls are essential for serious HF work.

### L-band Antenna (Inmarsat, Iridium)

For L-band reception (1525-1660 MHz), a **patch antenna** or **helix antenna** with a low-noise amplifier (LNA) is required.

**Patch antenna**: 8-10 dBi gain, circular polarization, flat form factor. Often combined with LNA in a single housing.

**Helix antenna**: Quadrifilar helix (QFH) provides wider beamwidth for LEO satellite reception (Iridium).

**Commercial options**: Outernet L-band patch + LNA ($80), custom-built patches from RTL-SDR blog.

## Part 5: Legal and Ethical Framework

### ITU Region Licensing

Radio frequencies are allocated internationally by the International Telecommunication Union (ITU) and administered by national regulators. The three ITU regions are:

- **Region 1**: Europe, Africa, Middle East, Northern Asia (e.g., ETSI standards, Ofcom, BNetzA)
- **Region 2**: Americas (e.g., FCC, IFT, Anatel)
- **Region 3**: Asia-Pacific (e.g., MIC Japan, ACMA Australia, KCC Korea)

Most licensed services (aviation, maritime) have internationally harmonized frequencies because aircraft and vessels cross regions. Amateur radio allocations vary slightly by region (e.g., 2m APRS is 144.39 MHz in US/Region 2 but 144.64 MHz in Europe/Region 1).

### FCC Part Numbers (US Reference)

| Part | Service | Examples |
|------|---------|----------|
| **Part 15** | Unlicensed ISM devices | 433/868/915 MHz IoT, keyfobs (covered in `sdr-rf-attack`) |
| **Part 80** | Maritime stations | AIS, maritime VHF voice, DSC |
| **Part 87** | Aviation stations | ADS-B, ACARS, VDL Mode 2, ATC voice, NDB |
| **Part 90** | Private land mobile | Public safety pagers (police, fire, EMS) |
| **Part 97** | Amateur radio | APRS, amateur VHF/UHF voice and data |

Transmitting without a license under these parts is a violation of the Communications Act of 1934 (47 USC 301) and can result in FCC enforcement actions (NOVs, forfeitures up to $19,639 per violation in 2021 dollars) and criminal prosecution.

### FCC Part 15 vs Part 97

This distinction is frequently confused in security work:

**Part 15 (Unlicensed)**: Covers intentional, unintentional, or incidental radiators operated without a license. Sub-GHz ISM band devices (433/868/915 MHz keyfobs, IoT) are Part 15. Transmission power is strictly limited (typically < 1 watt EIRP). Receivers are unrestricted.

**Part 97 (Amateur Radio)**: Covers licensed amateur radio service. Operators must pass an examination to receive a license (Technician, General, Extra class in the US). Licensees have extensive transmit privileges on amateur bands (160m through 1.2cm and beyond) at significant power levels (up to 1500 watts PEP). APRS at 144.39 MHz is Part 97 -- receiving is unrestricted, transmitting requires an amateur license.

### Red-Team Rules of Engagement

For engagements involving licensed band assessment:

**Receive-only is generally permitted**: Passive reception of unencrypted licensed broadcasts (ADS-B, AIS, ATC voice, ACARS, POCSAG) is legal in most jurisdictions. Document the legal basis in the engagement letter. Even when legal, consider whether acting on received data is appropriate (e.g., not disclosing PHI from pagers).

**Active transmission requires explicit authorization**: Any transmission on licensed bands requires either (a) the operator holding the appropriate license (FCC Part 80/87/97 in the US) or (b) explicit coordination with the licensee and conduct within a Faraday cage. Even authorized TX research should be in a shielded enclosure to prevent interference.

**No interference with safety services**: Aviation, maritime distress (DSC), and public safety communications are safety-of-life services. Active testing that risks interference is strictly prohibited. A false DSC distress alert could divert Coast Guard resources from a real emergency.

**PHI and PII handling**: Decoded pager messages containing patient data, names, or addresses must be handled as PHI under HIPAA. Redact before including in reports. Do not store raw decoded pager data beyond the engagement period.

**Coordination with facility operators**: For assessments at or near airports, ports, hospitals, or public safety facilities, coordinate with the facility operator before any RF testing. A hospital may not appreciate having their pager fleet audited without prior notice.

**Incident reporting**: Any unintended interference with licensed services must be reported immediately to the FCC (in the US) and to the affected service operator. Document any incidents thoroughly.

### Jurisdiction-Specific Legal Frameworks

**United States**: FCC regulations govern radio transmissions (47 CFR). 47 USC 605 prohibits unauthorized interception and disclosure of radio communications (with exceptions for public broadcasts). The Electronic Communications Privacy Act (ECPA) may apply to intercepted communications. CALEA covers cellular interception (not this skill's scope).

**European Union**: ETSI standards and national telecommunications laws apply. The General Data Protection Regulation (GDPR) applies to any personal data in decoded traffic (e.g., names in pager messages).

**United Kingdom**: Wireless Telegraphy Act 2006 prohibits unauthorized reception of certain transmissions. The Investigatory Powers Act (RIPA/IPA) covers interception. Ofcom enforces radio regulations.

**Australia**: Radiocommunications Act 1992 governs radio operations. The Telecommunications (Interception and Access) Act 1979 covers interception. ACMA is the regulator.

**International waters**: Maritime communications are governed by the ITU Radio Regulations and SOLAS (Safety of Life at Sea) convention. Vessels flagged to specific nations are subject to that nation's telecommunications law.

## Part 6: Lab Setup

### Basic Licensed Band Lab (Budget: $200)

A basic lab capable of 90% of receive-only licensed band work:

**Hardware**:

- RTL-SDR v3 ($30) -- covers 24-1766 MHz, ADS-B/AIS/ACARS/POCSAG/ATC voice
- AirSpy HF+ Discovery ($170) -- covers 9 kHz - 31 MHz HF band, NDB/HFDL/weather fax
- 1090 MHz collinear antenna ($25 homemade or $60 commercial)
- VHF marine antenna ($30-50)
- VHF air band discone ($90-100) or set of dedicated verticals
- HF magnetic loop or long wire ($50-250)

**Software (Kali Linux)**:

```bash
# Core SDR tools
sudo apt install -y hackrf rtl-sdr airspy gqrx gnuradio urh inspectrum sox

# Aircraft tracking
sudo apt install -y dump1090-mutability

# Pager decoding
sudo apt install -y multimon-ng

# APRS TNC
sudo apt install -y direwolf

# Weather fax
sudo apt install -y fldigi

# Build modern aircraft data link decoders from source
# dumpvdl2 (VDL Mode 2)
git clone https://github.com/szpajder/dumpvdl2.git
cd dumpvdl2 && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make -j4 && sudo make install

# dumphfdl (HFDL)
git clone https://github.com/szpajder/dumphfdl.git
cd dumphfdl && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make -j4 && sudo make install

# AIS-catcher
git clone https://github.com/jvde-github/AIS-catcher.git
cd AIS-catcher && mkdir build && cd build
cmake .. && make -j4 && sudo make install

# readsb (modern ADS-B decoder)
git clone https://github.com/wiedehopf/readsb.git
cd readsb && make -j4 RTLSDR=yes && sudo make install
```

### Advanced Lab with TX Research Capability (Budget: $1000+)

Add TX research capability for authorized work in a Faraday cage:

**Additional hardware**:

- HackRF One ($330) -- TX/RX for authorized replay research
- BladeRF 2.0 micro a4 ($480) -- full-duplex for protocol emulation
- Faraday cage / RF shielded enclosure ($500-$5000 depending on quality)
- RF power meter ($100-300) for verifying containment
- Assorted attenuators, SMA cables, connectors ($100)

**Faraday cage verification**:

```bash
# Verify Faraday cage containment before any TX research
# 1. Place HackRF inside cage with TX antenna
# 2. Place monitoring SDR (RTL-SDR) outside cage
# 3. Transmit known test signal inside cage
# 4. Verify no signal detected outside cage

# Inside cage (with HackRF):
hackrf_transfer -t test_signal.raw -f 1090000000 -s 2000000 -x 20

# Outside cage (with RTL-SDR monitoring):
rtl_power -f 1088M:1092M:100k -i 1 -e 30 outside_cage.csv
# Verify: no signal above noise floor at 1090 MHz
```

### Reference Data Sources

For correlating decoded data with real-world identifiers:

- **FAA Aircraft Registry**: https://registry.faa.gov/AircraftInquiry - ICAO24 hex to N-number and aircraft type
- **ITU MMSI Database**: Maritime Mobile Service Identity country/region lookup (first 3 digits = MID)
- **FlightAware Callsigns**: Airline callsign to ICAO callsign mapping (e.g., "AAL" = American Airlines)
- **ACARS Registry**: Aircraft tail number to operator and aircraft type mapping
- **Local Pager Frequency Lists**: Often published in public safety scanner guides for the engagement area

### Lab Workflows

**Receive-side intelligence workflow**:

1. Power on SDR hardware and verify with `hackrf_info` / `rtl_test -t`
2. Connect appropriate antenna for target service
3. Launch appropriate decoder (dump1090, AIS-catcher, multimon-ng, etc.)
4. Verify reception of expected signals
5. Calibrate PPM offset using `kal -g 40 -e` (legacy GSM) or known reference signal
6. Begin extended capture for traffic pattern analysis
7. Aggregate data with Python scripts (see payloads.md for examples)
8. Generate engagement-specific reports

**Protocol analysis workflow**:

1. Capture raw I/Q of target signal
2. Load in URH (Universal Radio Hacker) for interactive analysis
3. Auto-detect modulation parameters
4. Compare with known protocol structure (see payloads.md references)
5. Document protocol weaknesses for engagement report
6. Reference published research (Povolny, Costin, Trend Micro, DEF CON talks)

**Authorized TX research workflow (Faraday cage required)**:

1. Verify Faraday cage containment (no leakage)
2. Verify all SDR receivers in the cage are also shielded from outside signals
3. Document test signal parameters (frequency, modulation, power)
4. Execute authorized test transmissions
5. Capture receiver-side response for analysis
6. Document findings without impacting live spectrum
7. Power down TX equipment before opening cage

## Part 7: Engagement Workflow

### Pre-Engagement

1. **Scope definition**: Define which licensed services are in scope (e.g., "passive AIS reception at the client port facility")
2. **Legal review**: Confirm receive-only operation is permitted; document any TX research scope and Faraday cage requirements
3. **Site survey**: Visit engagement site to assess RF environment (background noise, existing licensed services, antenna mounting options)
4. **Hardware staging**: Prepare and test SDR hardware, antennas, and decoders before deployment

### During Engagement

1. **Deployment**: Install antennas with clear line-of-sight to target service (sky for ADS-B, water for AIS, etc.)
2. **Calibration**: Verify SDR PPM offset against known reference signals
3. **Baseline capture**: Run decoders for 24+ hours to establish baseline traffic patterns
4. **Anomaly detection**: Look for unexpected patterns (dark targets, ghost aircraft, PHI exposure in pagers)
5. **Protocol analysis**: Capture raw I/Q samples for detailed protocol security analysis
6. **Documentation**: Maintain detailed logs of all observations with timestamps and frequencies

### Post-Engagement

1. **Data aggregation**: Combine data from all decoders into unified report
2. **PHI/PII redaction**: Redact any sensitive data before inclusion in the report
3. **Cross-reference**: Validate observed aircraft/vessels against public registries
4. **Recommendations**: Provide concrete remediation recommendations (encrypted paging alternatives, AIS trust verification, etc.)
5. **Evidence preservation**: Maintain captured data per client retention requirements; securely delete per engagement scope

### Common Engagement Types

**Hospital pager PHI audit (HIPAA)**:

- Deploy RTL-SDR + multimon-ng near the hospital
- Monitor POCSAG/FLEX pager fleet for 7-14 days
- Audit decoded messages for PHI patterns (names, MRNs, room numbers)
- Generate HIPAA exposure report with quantified PHI rate
- Recommend migration to encrypted paging or secure messaging

**Maritime facility assessment**:

- Deploy RTL-SDR + AIS-catcher at the port facility
- Monitor vessel traffic for 7-14 days
- Identify dark targets (vessels with AIS off)
- Document baseline vessel traffic patterns
- Provide OPSEC recommendations for the facility

**Aviation facility assessment**:

- Deploy RTL-SDR + dump1090 + ACARSDeco at the airport-adjacent facility
- Monitor aircraft traffic and airline comms for 7-14 days
- Document ADS-B traffic patterns and ACARS message content
- Identify any anomalies (ghost aircraft, unusual callsigns)
- Provide OPSEC recommendations for the facility

**Critical infrastructure RF perimeter survey**:

- Deploy wideband SDR survey equipment at the facility perimeter
- Scan HF/VHF/UHF bands for 24+ hours
- Identify all licensed services present (expected and unexpected)
- Document any unauthorized RF devices
- Provide RF perimeter security recommendations

## Part 8: Defensive Recommendations for Licensed Services

### For Aviation Facility Operators

- **ADS-B trust verification**: Cross-reference received ADS-B with multilateration (MLAT) and radar to detect spoofed aircraft
- **Aircraft data link monitoring**: Monitor ACARS/VDL Mode 2 for sensitive operational data leakage
- **ATC voice OPSEC**: Document which ATC frequencies are audible from the facility and provide guidance on sensitive communications

### For Maritime Facility Operators

- **AIS dark target monitoring**: Maintain a list of expected vessels and detect when any go dark (AIS off)
- **AIS spoofing detection**: Cross-reference AIS positions with radar and visual confirmation
- **DSC false alert awareness**: Train operators on the DSC false alert problem and response procedures

### For Healthcare Facility Operators (HIPAA)

- **Pager PHI audit**: Regular audits of pager fleet for PHI exposure (quarterly recommended)
- **Migration planning**: Plan migration from unencrypted POCSAG/FLEX to encrypted paging or secure mobile messaging
- **HIPAA training**: Include pager PHI exposure in annual HIPAA training for clinical and dispatch staff

### For Public Safety Facility Operators

- **Pager dispatch OPSEC**: Audit public safety pager fleet for sensitive dispatch data exposure
- **Coordination with paging provider**: Ensure paging provider uses encrypted channels for sensitive operations
- **Migration planning**: Plan migration to encrypted P25 or TETRA voice/data systems

## Part 9: Quick Reference Cheat Sheet

```bash
# === Start dump1090 for ADS-B (web GUI on :8080) ===
dump1090 --net --gain 40 --aggressive --quiet &

# === Start AIS-catcher for maritime vessels ===
AIS-catcher -u 12345 -g 40 -v &

# === Start multimon-ng for POCSAG pagers (157.775 MHz example) ===
rtl_fm -f 157.775e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a POCSAG1200 -a FLEX -

# === Start acarsdec for ACARS (131.550 MHz) ===
acarsdec -r 0 131550000 -g 40 -v &

# === Start dumpvdl2 for VDL Mode 2 (136.975 MHz) ===
dumpvdl2 --gain 40 --output decoded:text:file:stdout &

# === Start dumphfdl for HFDL (HF bands) ===
dumphfdl --gain 40 2941000 5455000 8927000 11306000 15025000 17922000 &

# === Start APRS decode (144.39 MHz US) ===
rtl_fm -f 144.39e6 -s 22050 -g 40 - | \
  multimon-ng -t raw -a AFSK1200 -

# === Listen to ATC voice AM (121.5 MHz guard) ===
rtl_fm -M am -f 121.5e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# === Listen to maritime VHF Channel 16 ===
rtl_fm -M fm -f 156.8e6 -s 12000 -r 12000 -g 40 - | \
  play -r 12000 -t s16 -L -c 1 -

# === Spectrum survey of HF/VHF/UHF ===
rtl_power -f 100k:1500M:25k -i 10 -e 3600 -g 40 survey.csv

# === Calibrate RTL-SDR PPM (legacy GSM) ===
kal -g 40 -e
```

## Part 10: References and Further Reading

### Academic Papers and Research

- Povolny, P. & Wang, S. (2012). "On the Security of the ADS-B Protocol." - Seminal ADS-B security analysis
- Costin, A. & Francillon, A. (2012). "Ghost in the Air (Rerouted): On ADS-B and ATC Vulnerabilities." - ADS-B attacks with RTL-SDR
- Costin, A. (2012+). Continued aircraft protocol research including Mode S and VDL Mode 2
- Trend Micro Forward-Looking Threat Research (2019-2020). Maritime AIS spoofing documentation

### DEF CON and Conference Presentations

- Barisani, A. & Mancini, M. (DEF CON 18). "Pager networks: intercepting messages nationwide." - Pager PHI exposure documentation
- Phaedrus (DEF CON 22). "Plane Spotters Guide to Hacking Aircraft." - ACARS and VDL Mode 2 from attacker perspective
- Schaefer, M. et al. (various). Aviation communications security research

### Standards Documents

- **ICAO Annex 10**: Aeronautical Telecommunications (covers ADS-B, VDL Mode 2, HFDL, ATC voice)
- **ITU-R M.1371**: Technical characteristics of AIS (Automatic Identification System)
- **ITU-R M.493**: Digital Selective Calling (DSC) system specifications
- **RTCA DO-260A**: ADS-B SARPS (Standards and Recommended Practices)
- **RTCA DO-224C**: VDL Mode 2 standards
- **ARINC 618/622**: ACARS protocol specifications
- **POCSAG**: Post Office Code Standardization Advisory Group (BC/RC/CCIR Recommendation 584)
- **Motorola FLEX**: FLEX protocol reference documentation

### Online Communities and Resources

- **RTL-SDR.com**: Community blog and tutorials (https://rtl-sdr.com)
- **ADS-B Exchange**: Unfiltered ADS-B aggregator (https://adsbexchange.com)
- **FlightAware**: Global flight tracking with PiAware receiver program (https://flightaware.com)
- **MarineTraffic**: Global vessel tracking (https://marinetraffic.com)
- **VesselFinder**: Alternative vessel tracking (https://vesselfinder.com)
- **FAA Aircraft Registry**: ICAO24 to aircraft registration lookup (https://registry.faa.gov/AircraftInquiry)
- **ITU MMSI Database**: Maritime Mobile Service Identity country lookup

### Hardware Documentation

- **RTL-SDR.com V3**: https://rtl-sdr.com/BUYING/ -- RTL-SDR v3 documentation and purchasing
- **HackRF One**: https://greatscottgadgets.com/hackrf/ -- HackRF documentation
- **Nuand BladeRF**: https://www.nuand.com/ -- BladeRF documentation
- **AirSpy**: https://airspy.com/ -- AirSpy product documentation
- **Analog Devices PlutoSDR**: https://wiki.analog.com/university/tools/pluto -- PlutoSDR documentation
- **SDRplay**: https://www.sdrplay.com/ -- SDRplay RSP product documentation

### Decoder Tool Documentation

- **dump1090-mutability**: https://github.com/adsbxchange/dump1090-mutability
- **readsb**: https://github.com/wiedehopf/readsb
- **dump978**: https://github.com/mutability/dump978
- **AIS-catcher**: https://github.com/jvde-github/AIS-catcher
- **multimon-ng**: https://github.com/EliasOenal/multimon-ng
- **dumpvdl2**: https://github.com/szpajder/dumpvdl2
- **dumphfdl**: https://github.com/szpajder/dumphfdl
- **direwolf**: https://github.com/wb2osz/direwolf
- **fldigi**: https://sourceforge.net/projects/fldigi/
- **URH (Universal Radio Hacker)**: https://github.com/jopohl/urh
- **GNU Radio**: https://www.gnuradio.org/

### Legal and Regulatory References

- **FCC Rules**: 47 CFR (Code of Federal Regulations), especially Parts 80, 87, 90, 97
- **ITU Radio Regulations**: https://www.itu.int/pub/R-REG-RR
- **ECPA (US)**: Electronic Communications Privacy Act, 18 USC 2510-2523
- **CALEA (US)**: Communications Assistance for Law Enforcement Act (cellular only, out of scope)
- **GDPR (EU)**: General Data Protection Regulation, applies to personal data in decoded traffic
- **Wireless Telegraphy Act 2006 (UK)**: Governs unauthorized reception of certain transmissions
- **Radiocommunications Act 1992 (Australia)**: Governs radio operations

## Conclusion

Licensed HF/VHF/UHF radio assessment is a high-value, low-risk engagement activity when conducted as receive-side intelligence. The inherent insecurity of ADS-B, AIS, ACARS, and pager protocols -- designed in an era before software-defined radio democratized RF reception -- creates a rich surface for OPSEC findings and remediation recommendations.

The defining principle of this skill is **asymmetry**: receivers can map aircraft, vessels, pagers, and tactical voice traffic without transmitting a single photon, while transmitters face severe legal consequences for unauthorized operation. Engagement deliverables should emphasize receive-side intelligence, protocol security documentation, and concrete remediation recommendations -- with transmit-side attacks (spoofing, jamming) documented as research context only, never executed outside a Faraday cage.

For engagement work, the standard lab kit is an RTL-SDR v3 ($30) covering 90% of receive-only work, plus an AirSpy HF+ Discovery ($170) for serious HF analysis. Add a HackRF One ($330) and a Faraday cage for authorized TX research. Total investment of $200-$1000 supports the full range of licensed band assessment deliverables documented in this playbook.

The next frontier of licensed band security is cryptographic authentication. ADS-B Sec (proposed authentication), AIS-S (secure AIS), and LDACS (next-generation aviation data link with built-in security) are all in various stages of standards development. Until these are deployed, the licensed band remains a rich target for receive-side intelligence and protocol security research.
