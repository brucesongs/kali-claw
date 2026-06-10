# VoIP/SIP Attack Test Cases

> This file is a companion to `SKILL.md`, providing structured VoIP/SIP attack test case templates.
> Purpose: Check each item during penetration testing to ensure no critical VoIP attack vectors are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-VXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. SIP Device Discovery and Fingerprinting](#a-sip-device-discovery-and-fingerprinting)
- [B. SIP Extension Enumeration](#b-sip-extension-enumeration)
- [C. SIP Authentication Testing](#c-sip-authentication-testing)
- [D. VLAN Segmentation Bypass](#d-vlan-segmentation-bypass)
- [E. VoIP Eavesdropping](#e-voip-eavesdropping)
- [F. SIP Flood DoS](#f-sip-flood-dos)
- [G. IAX2 Flood DoS](#g-iax2-flood-dos)
- [H. RTP Interception](#h-rtp-interception)

---

## A. SIP Device Discovery and Fingerprinting

### TC-V001 | SIP Device Scanning and Fingerprinting

- **Severity**: HIGH
- **Objective**: Identify and fingerprint all SIP devices on the target network including PBX type, version, and supported SIP methods
- **Prerequisites**: Network access to target subnet, knowledge of VoIP VLAN IP range
- **Test Steps**:
  1. Use `svmap` to scan the target subnet for SIP-responsive devices: `svmap 10.0.0.0/24`
  2. Run `nmap -sU -sV -p 5060` on discovered hosts for version detection
  3. Probe each discovered device with `sipsak -s sip:100@target.lab` to collect User-Agent and Server headers
  4. Document PBX type, version, and supported SIP methods from responses
- **Expected Results**: All SIP devices (PBX servers, IP phones, SIP proxies, ATA adapters) are identified with vendor/version fingerprint. Devices responding without authentication are flagged.
- **Reference**: payloads.md Section 1 - SIP Device Reconnaissance

---

## B. SIP Extension Enumeration

### TC-V002 | SIP Extension Enumeration via OPTIONS/REGISTER

- **Severity**: HIGH
- **Objective**: Enumerate valid SIP extension numbers and determine which extensions require authentication versus accept unauthenticated requests
- **Prerequisites**: At least one SIP device identified, valid SIP domain or IP address
- **Test Steps**:
  1. Use `svwar` to enumerate extensions in the range 100-999: `svwar -e 100-999 10.0.0.1`
  2. Switch to OPTIONS method for stealthier probing: `svwar -m OPTIONS -e 100-9999 10.0.0.1`
  3. Test with REGISTER method to identify which extensions exist and require authentication: `svwar -m REGISTER -e 1000-1999 10.0.0.1`
  4. Manually probe interesting extensions with `sipsak -I -s sip:EXT@target.lab`
  5. Compile list of valid extensions, noting which require authentication and which do not
- **Expected Results**: Valid SIP extensions are enumerated. Extensions responding without authentication (200 OK to unauthenticated requests) are critical findings. Extension numbering patterns are identified.
- **Reference**: payloads.md Section 2 - SIP Extension Enumeration

---

## C. SIP Authentication Testing

### TC-V003 | SIP Password Cracking Against Valid Extensions

- **Severity**: CRITICAL
- **Objective**: Crack SIP extension passwords through dictionary attacks to gain unauthorized registration and call capabilities
- **Prerequisites**: Valid extension numbers enumerated (from TC-V002), wordlist prepared
- **Test Steps**:
  1. Test default credentials first: attempt registration with extension matching password (e.g., 100/100, admin/admin)
  2. Run `svcrack` against each valid extension: `svcrack -u 100 -d /usr/share/wordlists/rockyou.txt 10.0.0.1`
  3. Use rate limiting to avoid lockout/ban: `svcrack -u 100 -d wordlist.txt -r 2 10.0.0.1`
  4. Confirm cracked credentials by registering successfully: `sipsak -U -s sip:100@target.lab -u 100 -a crackedpassword`
  5. Document all extensions with cracked credentials
- **Expected Results**: Weak or default passwords on SIP extensions are discovered. Successful registration confirms credential validity. Accounts with no authentication requirement are flagged as CRITICAL.
- **Reference**: payloads.md Section 3 - SIP Password Cracking

---

## D. VLAN Segmentation Bypass

### TC-V004 | VLAN Hopping into VoIP Network

- **Severity**: HIGH
- **Objective**: Gain access to the voice VLAN through CDP spoofing or DHCP manipulation to reach VoIP devices
- **Prerequisites**: Physical or logical access to target network switch port, network interface in promiscuous mode
- **Test Steps**:
  1. Capture CDP packets to identify voice VLAN ID: `tcpdump -i eth0 -nn -vve ether dst 01:00:0c:cc:cc:cc`
  2. Run `voiphopper -i eth0 -C` to automatically join voice VLAN via CDP spoofing
  3. If CDP fails, attempt DHCP-based discovery: `voiphopper -i eth0 -D`
  4. If VLAN ID is known from CDP capture, manually create tagged interface: `ip link add link eth0 name eth0.100 type vlan id 100 && dhclient eth0.100`
  5. Scan voice VLAN for SIP devices: `svmap -i eth0.100 10.0.100.0/24`
  6. Verify whether data VLAN can reach voice VLAN devices (cross-VLAN ACL test)
- **Expected Results**: Attacker gains IP address on voice VLAN. SIP devices on voice VLAN become reachable from attacker position. If voice and data VLANs are not properly isolated, all VoIP devices are accessible.
- **Reference**: payloads.md Section 9 - VLAN Hopping into VoIP Networks

---

## E. VoIP Eavesdropping

### TC-V005 | RTP Stream Interception and Audio Decoding

- **Severity**: CRITICAL
- **Objective**: Capture and decode unencrypted RTP voice streams to demonstrate eavesdropping vulnerability
- **Prerequisites**: Access to voice VLAN or network path between VoIP endpoints, active calls in progress
- **Test Steps**:
  1. Capture RTP traffic on voice VLAN: `tcpdump -i eth0.100 -w voip_capture.pcap 'udp portrange 10000-20000'`
  2. While capture runs, ensure active calls are in progress on target extension
  3. Analyze PCAP in Wireshark: Telephony -> RTP -> RTP Streams to identify active streams
  4. Decode audio using Wireshark RTP player or command-line extraction with `tshark` + `sox`
  5. Verify whether SRTP is in use — if RTP payloads are not decodable, encryption is likely active
  6. Document the ability (or inability) to decode voice conversations
- **Expected Results**: Unencrypted RTP streams are captured and decoded into audible conversations. If SRTP is active, note that encryption prevents eavesdropping but do not mark as a finding (this is the expected secure state).
- **Reference**: payloads.md Section 4 - VoIP Eavesdropping

---

## F. SIP Flood DoS

### TC-V006 | SIP INVITE Flood Denial of Service

- **Severity**: HIGH
- **Objective**: Determine the SIP server flood threshold at which legitimate call processing degrades or fails
- **Prerequisites**: Explicit written authorization for DoS testing, target SIP server IP and domain, baseline measurement of normal call capacity
- **Test Steps**:
  1. Measure baseline: verify target can process test calls normally before flooding
  2. Launch INVITE flood with conservative packet count: `inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 1000`
  3. Attempt to place a legitimate test call during the flood
  4. Gradually increase flood intensity: 5000, 10000, 50000 packets
  5. At each level, test whether legitimate calls can still be established
  6. Record the threshold at which legitimate call processing degrades or fails
  7. After testing, verify full recovery of SIP services
- **Expected Results**: At some flood threshold, the SIP server stops processing legitimate calls. Document the minimum packet rate that causes degradation. Note whether the server recovers automatically or requires manual intervention.
- **Reference**: payloads.md Section 6 - VoIP DoS - SIP Flood

---

## G. IAX2 Flood DoS

### TC-V007 | IAX2 Protocol Flood Against Asterisk

- **Severity**: HIGH
- **Objective**: Test Asterisk IAX2 service resilience against protocol flood attacks that may affect call processing
- **Prerequisites**: Explicit written authorization for DoS testing, Asterisk PBX identified with IAX2 service (UDP 4569) open
- **Test Steps**:
  1. Verify IAX2 service is running: `nmap -sU -p 4569 10.0.0.1`
  2. Measure baseline IAX2 call performance
  3. Launch IAX2 flood: `iaxflood 10.0.0.1 4569 1000`
  4. Test legitimate IAX2 call during flood
  5. Increase flood intensity incrementally
  6. Document degradation threshold and recovery behavior
- **Expected Results**: IAX2 flood consumes Asterisk resources, degrading or blocking IAX2 call processing. The server may also show increased CPU/memory load affecting SIP processing on the same host.
- **Reference**: payloads.md Section 8 - VoIP DoS - IAX2 Flood

---

## H. RTP Interception

### TC-V008 | RTP Stream Disruption via Packet Flood

- **Severity**: MEDIUM
- **Objective**: Assess RTP stream resilience by flooding identified RTP ports to degrade or terminate active voice calls
- **Prerequisites**: Explicit written authorization for DoS testing, identified RTP port of active call, active call in progress for testing
- **Test Steps**:
  1. Establish a test call between two extensions
  2. Identify the RTP ports in use via SIP INVITE/200 OK SDP exchange or packet capture
  3. Flood the identified RTP port: `rtpflood 10.0.0.5 10000 1000`
  4. Assess call quality during the flood (audio degradation, dropouts, disconnection)
  5. Test with increasing flood intensity
  6. Document the impact on call quality and stability
- **Expected Results**: RTP flood causes audio quality degradation (jitter, packet loss). At higher intensities, calls may drop entirely. This demonstrates the lack of RTP stream protection and rate limiting.
- **Reference**: payloads.md Section 7 - VoIP DoS - RTP Flood

---

## Remediation and Defense Summary

### SIP Infrastructure Defense

- Enforce strong authentication on all SIP endpoints; disable unauthenticated registrations
- Implement SIP over TLS (sips) to encrypt signaling traffic
- Deploy SRTP to encrypt RTP media streams and prevent eavesdropping
- Use VLAN segmentation to isolate voice traffic from data networks
- Rate-limit SIP INVITE and REGISTER requests at the session border controller (SBC)

### VoIP Network Defense

- Disable CDP on ports facing non-Cisco devices; use 802.1X for voice VLAN authentication
- Deploy intrusion detection signatures for SIP and RTP flood patterns
- Implement quality-of-service (QoS) policing to limit RTP bandwidth per endpoint
- Monitor for ARP spoofing on voice VLAN using dynamic ARP inspection
- Block outbound SIP registration to external servers from internal endpoints

---

## Pass Criteria Checklist

- [ ] All SIP devices identified with vendor/version fingerprint
- [ ] Valid extensions enumerated with authentication status documented
- [ ] Weak/default passwords cracked and verified through registration
- [ ] Voice VLAN accessed via CDP or DHCP hopping
- [ ] RTP streams captured and decoded to audible audio
- [ ] SIP flood threshold documented with degradation point identified
- [ ] IAX2 service tested for flood resilience
- [ ] RTP flood impact on call quality measured and documented
