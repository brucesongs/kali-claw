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
- [I. Toll Fraud](#i-toll-fraud)
- [J. Session Hijacking](#j-session-hijacking)
- [K. Signaling Injection](#k-signaling-injection)
- [L. Transport Security Downgrade](#l-transport-security-downgrade)

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

## I. Toll Fraud

### TC-V009 | Toll Fraud via Default Credentials and International Dialing Abuse

- **Severity**: CRITICAL
- **Objective**: Demonstrate unauthorized long-distance/international call placement through a VoIP platform with default or weak administrative credentials, quantifying potential financial exposure
- **Prerequisites**: Authorized lab or engagement scope explicitly covering toll-fraud scenarios; FreeSWITCH/Asterisk platform identified (default credential candidates from CVE-2019-19492 class); call plan with international destinations simulated in lab
- **Test Steps**:
  1. Verify event socket exposure: `nmap -p 8021 10.0.0.1` (FreeSWITCH ESL default 8021/TCP)
  2. Attempt default ClueCon authentication (CVE-2019-19492 class): `fs_cli -H 10.0.0.1 -P 8021 -x 'status'`
  3. On success, enumerate the dialplan: `fs_cli -x 'show dialplan'`
  4. Place a test call to a simulated international destination via the compromised platform: `fs_cli -x 'originate sofia/gateway/testgw/011441632960001 &echo'`
  5. On Asterisk targets, test AMI default exposure instead: `nmap -p 5038 10.0.0.1` then Originate action with guessed credentials
  6. Review CDR evidence of the unauthorized call and calculate per-minute cost exposure at published international rates
- **Expected Results**: Default/weak platform credentials allow administrative call origination. CDR confirms billable international call placement without user authorization. Report includes per-destination cost model and credential-rotation remediation.
- **Reference**: payloads.md Section 19 - Known VoIP/SIP CVEs

---

## J. Session Hijacking

### TC-V010 | SIP Registration Hijacking and re-INVITE Session Redirection

- **Severity**: HIGH
- **Objective**: Demonstrate takeover of an active SIP registration (or in-dialog session via re-INVITE) to redirect or absorb an established call leg
- **Prerequisites**: Authorized lab with softphones registered to a SIP registrar; ability to inject SIP messages on-path (lab MITM via ARP poisoning in the voice VLAN is pre-authorized); Wireshark/scapy
- **Test Steps**:
  1. Capture the target extension's REGISTER (with Contact header) and note registration interval: `tshark -i eth0 -Y sip.Method=="REGISTER" -T fields -e sip.from.user -e sip.contact`
  2. Detect weak digest auth (missing nonce/stale algorithm) on re-REGISTER via registered contact change
  3. Craft a REGISTER replacing the Contact with attacker URI (when registrar accepts contact rewrite without re-auth): scapy `RFC3261` raw UDP injection to port 5060
  4. For in-dialog takeover, capture an established dialog's Call-ID/tags, then inject a re-INVITE updating the SDP connection address to the attacker host
  5. Verify inbound calls to the victim now ring at attacker-controlled endpoint (lab softphone)
  6. Restore the victim registration and confirm recovery
- **Expected Results**: Either (a) registrar enforces re-authentication on Contact change and re-INVITE (informational — hardened) or (b) registration/session redirection succeeds and the attacker endpoint receives the victim's calls (HIGH — full call-takeover demonstrated).
- **Reference**: payloads.md Section 5 and Section 14

---

## K. Signaling Injection

### TC-V011 | Forged BYE/CANCEL Call Teardown Injection

- **Severity**: MEDIUM
- **Objective**: Demonstrate premature call termination by injecting forged in-dialog BYE or CANCEL messages with guessed/observed dialog identifiers
- **Prerequisites**: Authorized lab voice VLAN access; active test calls; scapy or sipsak; knowledge that dialog identifiers (Call-ID, From-tag) may be predictable
- **Test Steps**:
  1. Establish a test call between two lab extensions
  2. Capture the dialog identifiers: `tshark -i eth0 -Y sip.Call-ID -T fields -e sip.Call-ID -e sip.r-uri`
  3. Evaluate identifier predictability (sequential Call-IDs, fixed From-tags) across 5 test calls
  4. Inject a forged BYE to the called party with the observed identifiers: scapy UDP injection carrying the crafted SIP BYE
  5. If identifiers were not directly observable, attempt blind guessing based on the observed pattern
  6. Confirm the call drops; repeat with CANCEL during ringing phase
  7. Verify whether the platform validates From-tag/To-tag pairing before honoring teardown
- **Expected Results**: Either (a) dialog validation rejects forged teardown (informational — hardened) or (b) calls terminate on forged BYE/CANCEL, demonstrating signaling-injection DoS with no credentials required (MEDIUM/HIGH depending on predictability).
- **Reference**: payloads.md Section 5 - VoIP Spoofing and Call Manipulation

---

## L. Transport Security Downgrade

### TC-V012 | SIPS/TLS Downgrade and SRTP Key Material Exposure

- **Severity**: HIGH
- **Objective**: Verify whether the voice platform (or endpoints) silently falls back from SIPS/TLS to plain UDP SIP and whether SRTP keying material (SDP crypto attributes) leaks over the downgraded leg
- **Prerequisites**: Authorized lab with a TLS-capable SIP infrastructure; endpoints configured for both SIPS and UDP; test position allows observing both transport legs
- **Test Steps**:
  1. Enumerate transport support: `nmap -sU -p 5060 --script sip-methods 10.0.0.1` and `nmap -p 5061 --script tls-alpn 10.0.0.1`
  2. Attempt a TLS connection, then send a plain-UDP REGISTER from the same identity; record which the registrar accepts and which it prefers
  3. Force downgrade paths: incomplete TLS handshake followed immediately by UDP REGISTER (fallback probing)
  4. On an established call, inspect the SDP for `a=crypto:` attributes over the negotiated signaling leg; if signaling fell back to UDP, capture the keying material: `tshark -i eth0 -Y sdp -T fields -e sdp.media_attr`
  5. Use exposed SRTP keys to decrypt the captured RTP stream of the lab call (srtp decrypt via libsrtp tools or scapy-rtp)
  6. Document which endpoints accepted the downgrade and whether media confidentiality was lost
- **Expected Results**: Either (a) the platform refuses UDP for TLS-provisioned identities and protects SDP crypto attributes (informational — hardened) or (b) silent transport downgrade leaks SRTP master keys on the wire, reducing "encrypted" calls to plain RTP exposure (HIGH).
- **Reference**: payloads.md Section 11 and Section 19

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
