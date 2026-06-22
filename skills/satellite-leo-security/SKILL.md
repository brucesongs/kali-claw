---
name: satellite-leo-security
description: Satellite and LEO communication security — Starlink, Kuiper, OneWeb, Iridium, Inmarsat, Viasat KA-SAT, HughesNet, DVB-S/S2, VSAT (iDirect/Hughes), GNSS receiver attacks, AcidRain wiper (Viasat 2022)
origin: kali-claw
version: 1.0
compatibility: Claude Code, Claude Sonnet 4.5+
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
metadata:
  domain: satellite-leo-security
  category: satellite
  tool_count: 13
  guide_count: 1
  mitre: T1557-Adversary-in-the-Middle
  keywords:
    - satellite
    - LEO
    - Starlink
    - Kuiper
    - Iridium
    - Inmarsat
    - Viasat
    - DVB-S
    - VSAT
    - GNSS
---


# Skill: Satellite & LEO Communication Security

> **Supplementary Files**:
> - `payloads.md` — Command catalogue organized by satellite family: Starlink (terminal hardware, boot chain, gRPC terminal APIs, starlinkground, Open Satellite Project), Iridium (gr-iridium L-band burst demod, SBD short-burst data, Iridium NEXT enumeration), Inmarsat (BGAN, FleetExpress, IsatPhone, Sned SBD), Viasat KA-SAT (SurfBeam2 firmware, AcidRain wiper analysis, TtDotMon), DVB-S/S2/S2X (leandvb software decoder, welle.io, blind scan, DVB-CSA descrambling in authorized lab), VSAT/iDirect/Hughes (9500/9800 modem shell, HM/HT attach, DNS hijack on uplink, provisioning abuse), GNSS receiver attacks (GPS-SDR-SIM, Galileo spoofing, RAIM detection). 60+ code blocks, 2,000+ lines.
> - `test-cases.md` — Structured test cases TC-SL-001..012: Starlink terminal enumeration, Iridium SBD burst decode, KA-SAT modem fingerprint, VSAT uplink hijack lab, GPS spoofing with GPS-SDR-SIM, DVB-S2 signal capture, Inmarsat BGAN terminal recon, iDirect modem shell access, multi-constellation GNSS attack, DVB-CSA descrambling (authorized lab), beam hopping observation, constellation tracking with gpredict. Plus a Verification Checklist and Defense/Mitigation Patterns section.
> - `guides/satellite-leo-security-playbook.md` — End-to-end satellite red team playbook: frequency band taxonomy (L/S/C/X/Ku/Ka/V), constellation comparison (LEO/GEO/MEO, latency, throughput, coverage), real-world incidents (Viasat KA-SAT AcidRain Feb 2022 with 5,800+ bricked terminals coincident with Russia-Ukraine invasion, Starlink SpaceX cyber-attacks claim 2022, Iridium pager SNMS, HughesNet DSL modem CSRF 2017, Apache Chukwa fleet monitoring), lab setup (HackRF/BladeRF/PlutoSDR + LNB for Ku-band, gr-iridium for L-band, leandvb for DVB-S2, GPS-SDR-SIM lab-only GNSS spoofing), defensive guidance (link-layer AES, DVB-RCS2 mutual auth, beam hopping, firmware signing).

## Summary

Satellite communication security covers the space segment, the ground segment, and the link between them — the radio path that carries broadband, voice, pager, TV, IoT, and navigation data to roughly four billion receivers worldwide. This skill targets commercial satellite communications: LEO broadband constellations (Starlink, Kuiper, OneWeb, Telesat Lightspeed), LEO narrowband (Iridium NEXT, Globalstar), GEO/MEO broadband (Inmarsat BGAN, Viasat KA-SAT, HughesNet Jupiter), GEO broadcast (DVB-S/S2/S2X, DIRECTV, Dish), VSAT enterprise networks (iDirect, Hughes PES, Newtec, Comtech), and the GNSS receiver attack class (GPS / Galileo / GLONASS / BeiDou / SBAS) at the receiver side only.

**Tools**: HackRF One / BladeRF 2.0 micro / PlutoSDR (with Ku/Ka LNB downconverter), GNU Radio with gr-iridium and gr-gnss, leandvb (software DVB-S2 decoder), welle.io (DVB GUI), GPS-SDR-SIM (GNSS spoofing lab), Wireshark with DVB/GNSS dissectors, Starlink DEMO / starlinkground, Open Satellite Project (opensat), RTL-SDR V3 / AirSpy R2, SDR# / SDRangel / GQRX, gpredict (satellite tracking), multimon-ng (POCSAG/FLEX/ACARS for VSAT paging), Universal Radio Hacker (URH).

**Domain**: satellite

**MITRE ATT&CK**: T1557-Adversary-in-the-Middle, T1485-Data Destruction (AcidRain-class wipers), T1499-Endpoint Denial of Service (satellite link jamming), T1098-Account Manipulation (VSAT provisioning abuse), T1584-Compromise Infrastructure (satellite uplink takeover).

## Differentiation

This skill is distinct from three adjacent RF attack skills:

- **`5g-telecom-attack`** — Terrestrial 3GPP cellular infrastructure (5GC AMF/SMF/UPF, RAN gNodeB, O-RAN, signaling PFCP/GTP/Diameter/SS7, IMSI catchers). All calls/signaling ride terrestrial cell-site backhaul; no satellite transponder is in the path. `satellite-leo-security` covers the case where the backhaul IS a satellite: Iridium Certus maritime, Inmarsat BGAN, Viasat KA-SAT, or a Starlink user terminal backhauling a remote cell. Where the two overlap (an SBA core reachable over a satellite backhaul), each skill owns its layer.
- **`hf-vhf-radio-attack`** — Licensed aviation and maritime VHF/HF bands (ATC voice, ACARS over VHF, AIS ship tracking, ADS-B at 1090 MHz, HF SELCAL, analog AM voice at 118–137 MHz). These are terrestrial aviation/maritime services, not satellite. `satellite-leo-security` covers ADS-B/AIS only when the uplink is satellite (e.g., Aireon ADS-B hosted on Iridium NEXT, or Starlink maritime AIS backhaul).
- **`sdr-rf-attack`** — Sub-GHz ISM band attacks (garage door remotes, wireless doorbells, weather stations, keyfobs, IoT sensors at 315/433/868/915 MHz). These are unlicensed short-range ISM devices. `satellite-leo-security` covers licensed Ku/Ka-band satellite downlinks (10.7–12.75 GHz) and L-band (1.5–1.6 GHz) which require an LNB or active antenna, not a naked Sub-GHz SDR.

In scope: Starlink / Kuiper / OneWeb / Telesat Lightspeed user terminals and their Ku/Ka downlinks, Iridium L-band bursts, Inmarsat BGAN, Viasat KA-SAT, HughesNet, DVB-S/S2 broadcast, VSAT (iDirect / Hughes / Newtec), GNSS receiver-side attacks. Out of scope: satellite uplink transmission (TX) — receive-only and terminal-side attack surface only; uplink work requires explicit national licensing authority and a Faraday cage.

## Description

Satellite communications have been an attack surface since the 1980s, when Captain Midnight broadcast a pornographic movie over HBO's Galaxy 1 transponder by injecting an unauthorized uplink signal during a televised match. The modern attack surface looks different but the underlying physics is unchanged: anyone within the footprint of a satellite downlink can receive, demodulate, and analyze its signal. The defense has always been cryptography — link-layer encryption (DVB-CSA for TV, AES for IP, custom for Iridium), conditional access systems (NDS/Videoguard, Irdeto, Viaccess), and per-terminal authentication (iDirect HOPPING plans, DVB-RCS2 mutual authentication). When the cryptography fails or is absent, the satellite becomes readable; when the terminal becomes remotely manageable by the attacker, it becomes brickeable.

This skill covers the eight things that distinguish satellite/LEO attacks from terrestrial RF attacks:

1. **LEO is moving — Doppler, beam handover, and footprint migration are first-class** — A Starlink or Iridium satellite at 550–780 km altitude moves across the sky at roughly 7 km/s; a single pass is 8–15 minutes. The user terminal must electronically steer its phased array, hand over the active beam to the next satellite in the constellation, and migrate its IP session across the gateway earth station in under 30 seconds. Each step is an attack surface: beam handover can be jammed or spoofed, gateway migration can leak session state, and the Doppler shift (tens of kHz at Ku-band) is a fingerprint that reveals which satellite the terminal is tracking.

2. **GEO is far — latency, bandwidth, and gateway centralization are the attack** — A GEO satellite sits at 35,786 km altitude. Round-trip latency is ~500 ms (vs. 30–60 ms for LEO); throughput per transponder is 1–10 Gbps shared across an entire beam's worth of terminals. The gateway earth stations are centralized — Viasat KA-SAT has a handful of gateways across Europe; severing or compromising one gateway can black out a continent. The AcidRain wiper (Feb 2022) demonstrated this: ~5,800 KA-SAT terminals in Ukraine and across Europe bricked coincident with the Russia-Ukraine invasion, by wiping the flash storage on the SurfBeam2 modem's MIPS-class firmware.

3. **DVB-S/S2 is broadcast — every receiver in the beam sees every stream** — DVB-S/S2/S2X (ETSI EN 300 421 / 302 307) uses a single wide carrier per transponder (typically 27–36 MHz wide, QPSK/8PSK/16APSK/32APSK modulation) that is downlinked across the entire beam footprint. Conditional Access (CA) scrambling (DVB-CSA, DVB-CISSA) provides confidentiality; the descrambling control words are delivered via Entitlement Control Messages (ECM) every 2–10 seconds. In authorized labs, DVB-CSA descrambling is a teaching exercise — a single lab receiver can recover the control words from the entitlement stream.

4. **VSAT networks are centralized — the hub is the crown jewel** — A VSAT (Very Small Aperture Terminal) enterprise network has a single Hub earth station (typically the iDirect or Hughes hub) and many remote terminals (the 1.2m Ku-band or 74cm Ka-band antennas on retail/branch sites). The hub routes all remote-to-remote traffic and aggregates Internet egress. Compromise of the hub (or its NMS — Network Management System) compromises the entire fleet; compromise of a single remote terminal (default credentials, exposed SSH, provisioning protocol abuse) gives lateral movement to the hub.

5. **GNSS attacks are receiver-side — the satellite cannot be touched** — The GPS / Galileo / GLONASS / BeiDou satellites broadcast their navigation messages (L1 C/A at 1575.42 MHz, L2C at 1227.60 MHz, L5 at 1176.45 MHz; Galileo E1/E5; BeiDou B1/B2) in a predictable format with weak spread-spectrum processing gain. A receiver-side attacker with a transmitter and lab/Faraday environment can synthesize a stronger counterfeit signal thatoverrides the authentic one — spoofing the receiver's computed position, time, or both. Real-world GPS spoofing has been documented for ships (C4ADS 2019, vessels in the Black Sea and Persian Gulf), drones, and business jets (over the Eastern Mediterranean and Iraq, 2023–2024). The defense is receiver-side: RAIM (Receiver Autonomous Integrity Monitoring), multi-constellation cross-check, and inertial navigation correlation.

6. **Maritime and aviation satellite are dual-attack-surface** — Inmarsat Fleet and Iridium Certus ship terminals, and Iridium / Inmarsat aviation terminals, have two distinct attack surfaces: (a) the satellite downlink/uplink (L-band, subject to jamming, spoofing, and lawful intercept), and (b) the on-board Ethernet/LAN side (subject to standard IT pentest of the bridge network, ECDIS, AIS transponder, and satcom router). The 2020 SST Dryad report on Russian GPS spoofing off the Syrian coast was a (a)-side attack; the 2018 CyberKeel report on VSAT terminals on merchant ships was a (b)-side attack. Both are valid pentest scopes.

7. **Fleet management and provisioning planes are C2 in disguise** — Every modern satellite terminal (Starlink, Viasat SurfBeam2, iDirect 9500/9800, Hughes HM/HT) is remotely managed by the operator via a dedicated management plane: Starlink uses gRPC over IPv6 from the terminal to a SpaceX NOC; Viasat SurfBeam2 uses TtDotMon and a TR-069-class provisioning flow; iDirect uses the Evolution or Velocity NMS over a dedicated in-band management VLAN on the hub; Hughes uses a DVB-RCS-class NMS. Each is a command-and-control channel with full firmware-update authority over the terminal fleet — and each has, historically, had weak or shared authentication.

8. **AcidRain-class wipers are the new threat model** — The Feb 2022 Viasat KA-SAT incident established that satellite terminal fleets are now a target of state-level data-destruction operations. The wiper — publicly attributed as AcidRain — was purpose-built for the MIPS-class uClinux environment of the SurfBeam2 modem, overwrote the flash storage with /dev/urandom output, and bricked ~5,800 terminals across Ukraine and several EU countries. The incident demonstrated that satellite terminals are now critical infrastructure — they backhaul Ukrainian military communications, ATMs, and wind-turbine SCADA — and that their boot chains and firmware update paths are an attack class, not just an attack vector.

This skill is the space-segment counterpart to `5g-telecom-attack` (terrestrial cellular) and `hf-vhf-radio-attack` (aviation/maritime VHF/HF). Where those skills cover the licensed RF that travels horizontally across the earth, this skill covers the licensed RF that travels vertically — up to the satellite and back down to a beam footprint that may cover an entire hemisphere.

## Use Cases

- **Starlink terminal assessment** — Authorized engagement against a deployed Starlink user terminal (Dishy) in a corporate/enterprise remote-site deployment. Enumerate the terminal's gRPC API, identify the boot chain and firmware update path, test the IPv6 prefix allocation for spoofing, characterize the geographic-restriction bypass surface.
- **Iridium L-band burst analysis** — Passive receive-only engagement: deploy a HackRF/BladeRF with a 1.6 GHz antenna and the gr-iridium GNU Radio flowgraph to capture Iridium L-band bursts, decode SBD (Short Burst Data) messages, characterize the transceiver channel mapping, and identify Iridium NEXT satellite passes via gpredict. Receive-only — no uplink.
- **Inmarsat BGAN / FleetExpress terminal pentest** — Grey-box assessment of an Inmarsat BGAN terminal deployed in a remote-site or maritime context. Identify the terminal firmware version, the provisioning flow, the IsatPhone voice encryption, the Sned SBD class, and the LAN-side attack surface (satcom router, attached devices).
- **Viasat KA-SAT modem analysis** — Lab-only engagement against a SurfBeam2 modem: extract the MIPS firmware, identify the TtDotMon management interface, characterize the boot chain and flash layout, and assess whether the terminal's firmware-update path could have delivered an AcidRain-class wiper. Authorized lab only.
- **DVB-S/S2 broadcast signal capture** — Authorized lab capture of a DVB-S/S2 downlink with leandvb (software decoder) or welle.io (GUI), characterization of the modulation, FEC, and symbol rate, identification of the ECM stream, and (in a fully authorized lab with a CA card) descrambling of the payload for teaching/verification.
- **VSAT enterprise network pentest** — Authorized engagement against an iDirect or Hughes VSAT network. Identify the hub and remote terminals, fingerprint the modem (9500/9800 for iDirect, HM/HT for Hughes), enumerate the NMS, test the provisioning protocol for abuse, identify weak per-terminal credentials, and assess lateral movement from remote terminal to hub.
- **GNSS receiver spoofing assessment (lab)** — Fully authorized Faraday-cage or open-field lab engagement against a GPS/Galileo receiver: generate a spoofed signal with GPS-SDR-SIM, broadcast it via a HackRF/BladeRF, observe the receiver's reported position, characterize the receiver's RAIM detection, and verify multi-constellation cross-check defenses.
- **Maritime/aviation satellite fleet review** — Defensive engagement: review a fleet of Inmarsat or Iridium ship/aircraft terminals for (a) fleet-wide terminal firmware versions and patch status, (b) LAN-side exposure of the satcom router, (c) GPS/GNSS spoofing-detection posture, (d) the C2/provisioning plane's authentication model.

## Core Tools

| Tool | Purpose | License / Notes |
|------|---------|-----------------|
| **HackRF One / BladeRF 2.0 micro / PlutoSDR** | General-purpose SDRs for the 1 MHz–6 GHz range. Paired with a Ku-band (10.7–12.75 GHz) or Ka-band (19.7–20.2 GHz) LNB downconverter (standard satellite TV LNB, ~$20) for receive-only satellite downlink capture. | GPL/Hardware. greatscottgadgets.com/hackrf, nuand.com, analog.com/plutosdr |
| **GNU Radio + gr-iridium + gr-gnss** | GNU Radio SDR framework; gr-iridium is the Iridium L-band burst demodulator; gr-gnss is the GNSS signal analyzer (GPS, Galileo, GLONASS, BeiDou). | GPL-3.0. gnuradio.org, github.com/muccy/gr-iridium, github.com/gnss-sdr/gnss-sdr |
| **leandvb** | Software DVB-S/DVB-S2/DVB-S2X demodulator. Reads an IQ file from RTL-SDR/HackRF/BladeRF and outputs a Transport Stream. The default tool for DVB-S2 receive-only lab work without dedicated hardware. | GPL-2.0. github.com/pabr/perfect-vines (leandvb) |
| **welle.io** | GUI DVB-T/DVB-S2 receiver. Real-time spectrum, signal, and TS view. Used for visual confirmation of DVB-S2 captures. | GPL-2.0. welle.io |
| **GPS-SDR-SIM** | GPS L1 C/A signal generator. Reads a RINEX ephemeris file and synthesizes an IQ signal that a HackRF/BladeRF can transmit (lab/Faraday only) to spoof a GPS receiver's computed position. | MIT. github.com/osqzsun/GPS-SDR-SIM |
| **Wireshark (with DVB/GNSS dissectors)** | Packet analysis. Dissects DVB MPE (Multi-Protocol Encapsulation), GSE (Generic Stream Encapsulation), DVB-S2 BBFRAME, GPS L1 C/A navigation messages, Galileo E1, Iridium SBD. | GPL-2.0. wireshark.org |
| **Starlink DEMO tool / starlinkground** | Reverse-engineered gRPC clients for the Starlink user terminal (Dishy). Expose terminal status, obstruction map, current satellite, beam, and boot state via the local gRPC API on 192.168.100.1:9200. | MIT. github.com/sparkydishy/starlink-grpc-tools |
| **Open Satellite Project (opensat)** | Suite of tools for parsing meteorological-satellite (GOES, Himawari, METEOSAT, METOP, NOAA) and other unencrypted satellite downlinks (LRIT, HRIT, APT). Useful as a training ground for satellite signal analysis. | GPL-3.0. opensatproject.org |
| **RTL-SDR V3 / AirSpy R2** | Low-cost receive-only SDRs. RTL-SDR V3 covers 100 kHz–1.7 GHz (incl. Iridium L-band with bias-tee active antenna). AirSpy R2 covers 24–1700 MHz with 10 MHz bandwidth. | GPL/Hardware. rtl-sdr.com, airspy.com |
| **SDR# / SDRangel / GQRX** | GUI SDR receivers. SDR# for Windows, SDRangel for cross-platform multi-channel, GQRX for macOS/Linux. Used for visual signal identification before recording. | GPL. airspy.com/sdrsharp, github.com/f4exb/sdrangel, gqrx.dk |
| **gpredict** | Real-time satellite tracking program. Predicts Iridium, Starlink, GPS, Inmarsat, and other passes from the observer's location using TLE (Two-Line Element) data from Celestrak. Essential for LEO capture planning. | GPL-2.0. gpredict.oz9aec.net |
| **multimon-ng** | Decoder for POCSAG (pager), FLEX (pager), and ACARS (aircraft) — used to decode VSAT paging and other narrowband satellite control channels. | GPL-2.0. github.com/EliasOenal/multimon-ng |
| **Universal Radio Hacker (URH)** | Reverse-engineering tool for unknown RF protocols. Records IQ, identifies modulation and framing, builds a decoder. Used for custom satellite IoT (Swarm, Astrocast, Kineis, Lacuna) and proprietary VSAT control links. | GPL-3.0. github.com/jopohl/urh |

## Methodology

The engagement methodology is organized in five phases. The default posture is **receive-only / passive**: in most jurisdictions, transmitting in licensed satellite bands (Ku 14.0–14.5 GHz uplink, Ka 28–30 GHz uplink, L-band 1.6 GHz uplink for Iridium/Inmarsat) without a national license is a criminal offense on par with cellular jamming. The only TX-side work this skill covers is GPS-SDR-SIM GNSS spoofing, and only inside an authorized Faraday cage or open-field test range.

### Phase 1: Reconnaissance (Passive, RX-Only)

- **Frequency survey** — Sweep the relevant downlink bands: L-band (Inmarsat 1525–1559 MHz, Iridium 1616–1626.5 MHz), Ku-band (10.7–12.75 GHz with a standard LNB downconverting to 950–2150 MHz IF), Ka-band (19.7–20.2 GHz with a Ka-band LNB). Use HackRF/BladeRF with osmocom_fft or SDRangel to identify active carriers. For Ku/Ka work the LNB is fed via coax into the SDR's 50-ohm input with a DC-block / bias-tee power.
- **Constellation tracking** — Use gpredict with current TLEs (Celestrak catalog) to predict Starlink, Iridium NEXT, GPS, Galileo, Inmarsat, and Viasat passes. Starlink's per-pass footprint is ~15 minutes per satellite; Iridium NEXT ~10 minutes; GPS satellites are GEO-like in apparent sky motion (8 hour semi-circles).
- **Beam footprint mapping** — For GEO satellites (Viasat KA-SAT at 9°E, Inmarsat I-4 at 64°E/54°W/178°E, Hughes Jupiter at 22°W/55°W/97°W, SES, Eutelsat), identify the beam footprint that covers the engagement location. Each beam is a distinct carrier set; VSAT NMSs are per-beam.
- **Terminal discovery (LAN-side)** — For on-prem engagements, nmap-sweep the management subnet for known terminal types: Starlink (192.168.100.1 gRPC), Viasat SurfBeam2 (192.168.0.1 web UI), iDirect 9500/9800 (192.168.1.1 SSH), Hughes HM/HT (192.168.0.1 web UI), Inmarsat BGAN (192.168.128.100).

### Phase 2: Signal Capture (RX-Only)

- **L-band capture (Iridium, Inmarsat)** — Set SDR center frequency to 1621.25 MHz (Iridium downlink), 1525–1559 MHz (Inmarsat). Sample rate 500 ksps minimum (Iridium channels are 31.5 kHz wide BDPSK/QPSK). Record to IQ file for offline gr-iridium processing.
- **Ku/Ka-band capture (Starlink, Viasat, Hughes)** — Connect LNB to SDR via bias-tee. Set SDR center frequency to the downconverted IF (typically 950–2150 MHz). Sample rate 2 Msps minimum for DVB-S2 (typical symbol rate 27.5 Msym/s requires a larger capture; multiple SDRs or a high-bandwidth SDR like BladeRF 2.0 micro xA4 or a dedicated DVB receiver card is preferred).
- **DVB-S2 demodulation** — Pipe the IQ capture through leandvb to recover the Transport Stream: `leandvb --vit 27500 --sr 27500000 --n helpers --in input.iq --out output.ts`. Verify TS structure with `dvbsnoop` or `ts2sec`.
- **GNSS capture (lab)** — For spoofing receiver-side analysis, capture authentic GPS L1 with a u-blox or HackRF; for spoofing TX-side work, GPS-SDR-SIM generates the IQ file (lab/Faraday only).

### Phase 3: Protocol & Firmware Analysis

- **DVB MPE/GSE decapsulation** — DVB-S2 carries IP via MPE (Multi-Protocol Encapsulation, ETSI EN 301 192) or GSE (Generic Stream Encapsulation, ETSI TS 102 606). Use Wireshark's DVB-MPE dissector to extract the IP payload from the TS.
- **Starlink gRPC enumeration** — Query the Dishy's local gRPC API (`grpcurl -plaintext -import-path . -proto starlink.proto 192.168.100.1:9200 list`), enumerate the device_info, obstruction_map, and current_satellite endpoints. Identify the firmware version and the boot chain.
- **Viasat SurfBeam2 firmware extraction** — In an authorized lab, dump the SurfBeam2 flash via the JTAG or serial console (the modem runs uClinux on a MIPS-class Broadcom SoC). Identify the TtDotMon interface, the firmware-update URL, and the boot loader.
- **iDirect / Hughes modem shell** — For authorized engagements, identify the modem's debug shell: iDirect 9500/9800 expose telnet/SSH on the LAN after engineering password recovery; Hughes HM/HT modems expose a hidden debug menu via CSRF-protected forms on the web UI.

### Phase 4: Active Test (Authorized Lab Only)

- **VSAT uplink DNS hijack (in-band, lab)** — On an authorized VSAT lab with the hub's cooperation, inject a spoofed DNS response on the uplink to test whether the hub forwards it to remote terminals. Verifies the security posture of the hub's uplink filtering.
- **GPS spoofing (Faraday cage)** — Use GPS-SDR-SIM to generate a spoofed L1 signal for a target position (e.g., 100 km from the lab's true position). Broadcast via HackRF into a Faraday cage containing the target GPS receiver. Verify the receiver's reported position shifts. Test multi-constellation receivers for cross-constellation detection.
- **DVB-CSA descrambling (authorized lab with CA card)** — In a lab authorized by the conditional-access provider, capture the ECM stream from a DVB-S2 carrier and test the descrambling latency. Do not redistribute the descrambled stream.

### Phase 5: Reporting

- **Frequency / spectrum evidence** — Provide IQ captures, spectrograms, and gpredict pass predictions. Document every RX-only capture with timestamp, antenna, LNB, SDR, gain setting, and observer location.
- **Firmware evidence** — Provide firmware hashes, extracted strings, identified boot chain, and any JTAG/serial logs. Do not redistribute the firmware image outside the engagement.
- **TX-side evidence (lab)** — For GPS spoofing, document the Faraday cage or open-field test range, the authorized test receiver, the spoofed position and the receiver's reported position before/during/after the test. Include the RAIM alert status if the receiver has one.
- **Defense recommendations** — Per-finding: link-layer encryption (DVB-RCS2 mutual auth, AES-GCM at IP layer), terminal firmware signing and secure boot, hub-side uplink filtering, GNSS receiver hardening (RAIM+, multi-constellation, inertial cross-check).

## Practical Steps

> All TX-side work (VSAT uplink, GPS spoofing broadcast, Iridium/Inmarsat uplink) is restricted to authorized lab / Faraday / open-field test range. The default posture is RX-only.

### Step 1 — Constellation Tracking with gpredict

```bash
# Install gpredict and update TLEs from Celestrak
sudo apt install gpredict
mkdir -p ~/.config/Gpredict/tle
# Download Starlink, Iridium NEXT, GPS, Galileo, Inmarsat TLEs
wget -q -O ~/.config/Gpredict/tle/starlink.txt https://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
wget -q -O ~/.config/Gpredict/tle/iridium.txt https://celestrak.org/NORAD/elements/gp.php?GROUP=iridium-NEXT&FORMAT=tle
wget -q -O ~/.config/Gpredict/tle/gps.txt https://celestrak.org/NORAD/elements/gp.php?GROUP=gps-ops&FORMAT=tle
wget -q -O ~/.config/Gpredict/tle/galileo.txt https://celestrak.org/NORAD/elements/gp.php?GROUP=galileo&FORMAT=tle
# Launch gpredict and select the engagement observer location
gpredict &
```

### Step 2 — L-band Capture (Iridium) with HackRF + gr-iridium

```bash
# Record 5 minutes of Iridium L-band at 1621.25 MHz
# Active antenna with bias-tee, or external LNA + 1.6 GHz antenna
hackrf_transfer -r iridium_$(date +%s).iq -f 1621250000 -s 2000000 -g 40 -l 40 -a 1 -d 300
# Demodulate bursts with gr-iridium
gr_iridium -r 2000000 -D iridium.iq | head
# Channel mapping: 12 ring-prioritized simplex channels, BDPSK at 50 kbps
```

### Step 3 — Ku-band DVB-S2 Capture with LNB + RTL-SDR

```bash
# Standard satellite TV LNB (PLL LO 9750/10600 MHz)
# Connect via bias-tee to RTL-SDR V3
# Tune to a known DVB-S2 carrier (e.g., Eutelsat at 10.920 GHz vertical)
# Downconverted IF: 10920 - 10600 = 320 MHz; verify with rtl_power
rtl_power -f 250M:450M:0.5M -g 40 -i 5s dvbs_scan.csv &
# Once a carrier is identified at, say, 1170 MHz IF, capture:
rtl_sdr -f 1170000000 -s 2400000 -g 40 -n 48000000 dvbs_capture.iq
# Demodulate with leandvb
leandvb --sr 27500000 --roll-off 0.35 --vit 27500 --in dvbs_capture.iq --out dvbs_output.ts 2> leandvb.log
# Inspect the recovered transport stream
dvbsnoop -n 10 dvbs_output.ts | head
```

### Step 4 — Starlink Dishy gRPC Enumeration

```bash
# Install grpcurl
sudo apt install grpcurl
# Get the Starlink gRPC schema (community-published proto)
git clone https://github.com/sparkydishy/starlink-grpc-tools.git
cd starlink-grpc-tools
# Enumerate endpoints (Dishy listens on 192.168.100.1:9200)
grpcurl -plaintext -import-path . -proto spacex/api/device/device.proto 192.168.100.1:9200 SpaceX.API.Device.Device
# Get device info: firmware version, hardware version, boot state
grpcurl -plaintext -import-path . -proto spacex/api/device/device.proto \
  -d '{}' 192.168.100.1:9200 SpaceX.API.Device.Device/Handle > device_info.json
# Get current obstruction map and the satellite the terminal is tracking
grpcurl -plaintext -import-path . -proto spacex/api/device/device.proto \
  -d '{}' 192.168.100.1:9200 SpaceX.API.Device.Device/GetObstructionMap > obstruction.json
```

### Step 5 — GPS Spoofing (Lab / Faraday Only) with GPS-SDR-SIM

```bash
# LAB / FARADAY ONLY — broadcasting GPS L1 without authorization is illegal
# Download a recent RINEX ephemeris (daily broadcast ephemeris from NASA CDDIS)
wget -q -O brdc.2026n.gz ftp://gdc.cddis.eosdis.nasa.gov/gnss/data/daily/2026/brdc/brdc0010.26n.gz
gunzip brdc.2026n.gz
# Generate a 60-second IQ for a spoofed position (lat=40, lon=-75, alt=100m)
# -e: ephemeris; -l: lat,lon,alt; -d: duration in seconds; -b: IQ bit width
gps-sdr-sim -e brdc0010.26n -l 400000,-750000,100 -d 60 -b 16
# Output: gpssim.bin (16-bit IQ at 2.6 Msps)
# Transmit via HackRF inside a Faraday cage
hackrf_transfer -t gpssim.bin -f 1575420000 -s 2600000 -a 1 -x 20 -R
# Verify the target receiver's reported position shifts to 40N, -75W
```

> The above command is reproducible only inside a Faraday cage. Transmitting on the GPS L1 band in any other context is a federal offense in most jurisdictions (e.g., US 47 USC § 301, § 333; EU RED Art. 9).

## Defense Perspective

Defenders of satellite terminal fleets, ground segments, and downlink receivers should harden the following surfaces:

- **Link-layer encryption** — All IP traffic over the satellite link should be AES-GCM encrypted at the link layer (DVB-RCS2, GSE-SEC, or vendor-specific — iDirect has linkAES, Hughes has LinkEncryption). Never rely on DVB-CSA / DVB-CISSA for IP traffic — those are CA systems for broadcast TV, not security for data.
- **Terminal firmware signing and secure boot** — All terminals should require signed firmware images (RSA-2048 / ECDSA P-256) and should refuse to boot unsigned or downgraded firmware. The AcidRain wiper (Viasat 2022) succeeded because the SurfBeam2 accepted unsigned or weakly-checked firmware updates over its management plane.
- **Management plane authentication** — Every terminal's remote management interface (Starlink gRPC, Viasat TtDotMon, iDirect NMS, Hughes DVB-RCS NMS) must enforce per-terminal mutual-TLS with certificates rotated on a defined cadence. Shared fleet-wide credentials are the default in legacy deployments — the Viasat incident showed the consequences.
- **Hub-side uplink filtering** — The hub earth station (or the gateway) must filter uplink traffic to reject spoofed DNS, ARP, and DHCP responses from compromised remote terminals. Without this, a single compromised VSAT remote can hijack DNS for the entire beam.
- **GNSS receiver hardening** — Multi-constellation receivers (GPS + Galileo + GLONASS + BeiDou) with RAIM+ (Receiver Autonomous Integrity Monitoring with fault detection and exclusion), inertial navigation cross-check, and the ability to flag position jumps inconsistent with dead reckoning. Single-constellation L1-only receivers are spoofable with commodity hardware.
- **Beam hopping observation** — Modern High-Throughput Satellites (Viasat, Hughes Jupiter, Inmarsat) use beam hopping (time-sliced illumination of multiple beams). Defenders can monitor the beam-hopping pattern as a side channel for anomalous activity; attackers cannot easily spoof beam hops without uplink transmission.
- **Fleet monitoring and integrity** — Centralized fleet monitoring (e.g., a SIEM ingest of terminal boot states, firmware hashes, configuration changes) is the only practical defense against an AcidRain-class wiper. The first terminals to be bricked in the Viasat incident were unobserved for hours.

## Reference Quick Map

| Surface | Tool | Skill Step |
|---------|------|-----------|
| Starlink Dishy gRPC | grpcurl + starlink-grpc-tools | Step 4 |
| Iridium L-band bursts | gr-iridium | Step 2 |
| Inmarsat BGAN L-band | SDRangel + URH | payloads.md §3 |
| Viasat KA-SAT SurfBeam2 | JTAG/serial + binwalk | payloads.md §4 |
| DVB-S/S2 downlink | leandvb + dvbsnoop | Step 3 |
| VSAT iDirect 9500/9800 | telnet/SSH shell | payloads.md §6 |
| GNSS spoofing (lab) | GPS-SDR-SIM + HackRF | Step 5 |
| Constellation tracking | gpredict | Step 1 |

## Tool Quick Reference

```text
# 13 tools used in this skill
hackrf / bladerf / plutosdr        # SDR hardware
gnuradio gr-iridium gr-gnss        # SDR framework + blocks
leandvb                            # DVB-S2 software demodulator
welle.io                           # DVB GUI receiver
gps-sdr-sim                        # GNSS spoofing signal generator
wireshark                          # Packet analysis with DVB/GNSS dissectors
starlink-grpc-tools                # Starlink Dishy gRPC client
opensat (Open Satellite Project)   # Meteorological-satellite downlink parsers
rtl_sdr / airspy                   # RX-only SDRs
sdrangel gqrx sdrsharp             # GUI SDR receivers
gpredict                           # Satellite tracking
multimon-ng                        # POCSAG/FLEX/ACARS decoder
urh (Universal Radio Hacker)       # RF protocol reverse engineering
```

## Legal & Ethical Notes

- **Frequency licensing** — Ku (14.0–14.5 GHz), Ka (28–30 GHz), L-band (1.626–1660.5 MHz for Iridium uplink, 1626.5–1660.5 MHz for Inmarsat uplink), and GPS L1 (1575.42 MHz) are licensed bands. Transmitting without authorization is a federal offense (US 47 USC § 301/§ 333; EU RED Art. 9; equivalent in most jurisdictions).
- **VSAT uplink authorization** — VSAT terminals operate under a per-terminal station license tied to a specific frequency, polarization, EIRP, and orbital slot. Unauthorized uplink transmission voids the license and is prosecutable.
- **GPS spoofing** — Even in a lab, broadcasting GPS L1 outside a Faraday cage is dangerous: it can disrupt aviation, maritime, and emergency-services receivers within kilometers. Lab-only.
- **Conditional access** — DVB-CSA descrambling without a CA card from the conditional-access provider is illegal in most jurisdictions (US DMCA § 1201, EU Copyright Directive Art. 6). Authorized lab only.
- **Dishy / SurfBeam2 / iDirect firmware** — Reverse-engineering a terminal's firmware may void its warranty and the operator's terms of service. Obtain written authorization from the terminal owner before extraction.

## Cross-References

- `5g-telecom-attack` — Terrestrial cellular infrastructure (3GPP 5GC, RAN, signaling).
- `hf-vhf-radio-attack` — Aviation/maritime VHF/HF (ATC voice, ACARS, AIS, ADS-B at 1090 MHz).
- `sdr-rf-attack` — Sub-GHz ISM (garage door, IoT sensors, keyfobs).
- `scada-ics-security` — Satellite terminals frequently backhaul SCADA (pipelines, wind turbines, remote substations). The Viasat 2022 incident disabled ~5,800 wind-turbine modems in Germany via Energis/Viasat.
- `digital-forensics` — Satellite terminal firmware extraction and post-incident wiper analysis (AcidRain class).
- `anti-forensics` — Wiper analysis methodology (AcidRain is the canonical satellite-side wiper).
- `hardware-security` — JTAG/serial extraction of terminal firmware, glitching, side channels.
