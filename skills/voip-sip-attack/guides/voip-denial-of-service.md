# VoIP Denial of Service Attacks

> Guide covering SIP INVITE flood, IAX2 flood, RTP flood attacks, and defense strategies for VoIP infrastructure.

## Overview

VoIP systems are particularly susceptible to denial-of-service attacks because they rely on real-time packet delivery with strict timing requirements. Unlike web applications that can tolerate latency, VoIP calls degrade noticeably with even small amounts of packet loss or delay. This guide covers three primary VoIP DoS attack vectors — SIP flooding, IAX2 flooding, and RTP flooding — along with the tools to test them and defensive strategies to recommend.

**Important**: DoS testing requires explicit written authorization. Always measure baselines before testing, use incremental intensity levels, and verify full service recovery after testing.

---

## SIP INVITE Flood with inviteflood

### How SIP INVITE Flood Works

A SIP INVITE flood overwhelms the target SIP server by sending massive volumes of INVITE requests. Each INVITE triggers the server to allocate resources for call setup — parsing the message, performing authentication (if required), generating responses, and potentially allocating media ports. At sufficient volume, the server exhausts its call processing capacity and cannot handle legitimate calls.

The `inviteflood` tool crafts raw SIP INVITE packets and sends them at high speed. It supports IP spoofing, custom SIP domains, and configurable flood rates.

### Running inviteflood

```bash
# Basic INVITE flood against SIP server
# Arguments: interface, source IP, destination IP, target extension, packet count
inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 10000

# Flood with spoofed source IP
inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 50000 -a 10.0.0.99

# Flood targeting SIP proxy (source and destination are the same)
inviteflood -i eth0 10.0.0.1 10.0.0.1 200@target.lab 100000

# Flood with line directory (ldir) request type
inviteflood -i eth0 10.0.0.1 10.0.0.5 ldir@target.lab 20000
```

### Testing Methodology

1. **Establish baseline**: Before flooding, verify that the target can process test calls normally. Record call setup time and success rate.

2. **Start with low intensity**: Begin with 1000 packets and observe the effect.

3. **Test during flood**: While the flood runs, attempt to place legitimate test calls. Record whether calls succeed, fail, or experience quality issues.

4. **Increment gradually**: Increase to 5000, 10000, 50000 packets. At each level, test legitimate call processing.

5. **Record degradation threshold**: Document the minimum packet rate that causes measurable call processing degradation.

6. **Verify recovery**: After stopping the flood, measure how long it takes for the server to return to normal operation.

### Impact Assessment

The impact of an INVITE flood varies by PBX implementation:

- **Asterisk**: May experience high CPU load, slow call processing, and eventually stop accepting new calls. Channel exhaustion is common.
- **Cisco CME/ISR**: Generally more resilient but can be overwhelmed at high volumes. May exhibit increased post-dial delay.
- **FreeSWITCH**: Handles moderate flooding well but degrades under sustained high-volume attacks.

Document the specific behavior observed for each target platform.

---

## IAX2 Flood with iaxflood

### Understanding IAX2 Protocol

The Inter-Asterisk Exchange protocol (IAX2) is used primarily between Asterisk PBX servers and IAX2-compatible endpoints. Unlike SIP, IAX2 multiplexes both signaling and media on a single UDP port (4569), making it an efficient but concentrated attack target.

IAX2 uses a binary protocol format rather than SIP's text-based format, which makes flood packets smaller and faster to process on the sending side.

### Running iaxflood

```bash
# Basic IAX2 flood against Asterisk server
# Arguments: target IP, target port, packet count
iaxflood 10.0.0.1 4569 1000

# Higher volume flood
iaxflood 10.0.0.1 4569 5000

# Flood from specific interface (e.g., voice VLAN interface)
iaxflood -i eth0.100 10.0.0.1 4569 2000

# Maximum volume flood
iaxflood 10.0.0.1 4569 10000
```

### When to Test IAX2 Flooding

Not every VoIP deployment uses IAX2. Before testing, verify that the target has IAX2 enabled:

```bash
# Check if IAX2 port is open
nmap -sU -p 4569 10.0.0.1

# Check for IAX2 responses
nmap -sU -sV -p 4569 10.0.0.1
```

IAX2 is most commonly found in Asterisk deployments. If the target is a different PBX platform (Cisco, Avaya, etc.), IAX2 testing may not be applicable.

### Dual-Protocol Impact

Asterisk servers often run both SIP (5060) and IAX2 (4569) on the same host. Flooding IAX2 may impact SIP processing as well due to shared system resources (CPU, memory, network buffer). Document whether the IAX2 flood has cross-protocol impact.

---

## RTP Flood with rtpflood

### How RTP Flooding Disrupts Calls

While SIP and IAX2 floods target the signaling plane (call setup), RTP flooding targets the media plane (voice/audio). An RTP flood sends garbage data to the RTP port of an active call, consuming bandwidth and causing audio degradation.

RTP flooding is most effective against active calls because the target endpoint must process incoming RTP packets to maintain call audio. Flooding with invalid or excessive RTP data causes jitter, packet loss, and eventually call drop.

### Running rtpflood

```bash
# Flood a specific RTP port
# Arguments: target IP, RTP port, packet count
rtpflood 10.0.0.5 10000 1000

# Higher volume flood
rtpflood 10.0.0.5 10000 10000

# Flood multiple RTP ports simultaneously
for port in 10000 10002 10004 10006; do
  rtpflood 10.0.0.5 $port 5000 &
done
```

### Identifying RTP Ports

RTP ports are negotiated during SIP call setup via the SDP payload. To identify the RTP ports for an active call:

1. Capture the SIP INVITE and 200 OK exchange.
2. Extract the media port from the SDP `m=audio` line.
3. Use this port as the target for rtpflood.

```bash
# Capture SIP signaling to find RTP port negotiation
tcpdump -i eth0 -w sip_setup.pcap udp port 5060 -c 20

# Extract media port from SDP
tshark -r sip_setup.pcap -Y 'sip' -T fields -e sdp.media.port
```

---

## Combined DoS Assessment

### Multi-Vector Testing

For comprehensive DoS assessment, test each vector independently first, then consider combined scenarios:

1. **SIP flood only**: Measures signaling plane resilience.
2. **IAX2 flood only**: Measures IAX2 service resilience.
3. **RTP flood only**: Measures media plane resilience during active calls.
4. **SIP + RTP combined**: Tests whether the server can handle both signaling and media attacks simultaneously.

### Measurement Criteria

For each test, document:

- **Packet rate sent**: Packets per second delivered to the target.
- **Call setup success rate**: Percentage of legitimate calls that succeed during the flood.
- **Post-dial delay**: Time from dialing to ring-back.
- **Audio quality**: MOS (Mean Opinion Score) degradation if measurable.
- **Recovery time**: Time for service to return to baseline after flood stops.
- **CPU/memory impact**: Resource utilization on the target if accessible.

---

## Defense Strategies

### SIP DoS Defenses

- **Rate limiting**: Implement per-source-IP rate limits on SIP messages. A typical threshold is 10-20 SIP messages per second per source IP.
- **Session Border Controllers (SBCs)**: Deploy SBCs that normalize SIP traffic, detect flood patterns, and drop malicious traffic before it reaches the PBX.
- **SIP-aware firewalls**: Use firewalls with SIP inspection modules that can identify and block anomalous SIP patterns.
- **Authentication enforcement**: Require authentication on all SIP methods to prevent unauthenticated INVITE floods.
- **Challenge-response throttling**: Increase the authentication challenge complexity during high-volume periods.

### RTP DoS Defenses

- **SRTP encryption**: While SRTP does not prevent flooding directly, it makes it harder for attackers to identify and target RTP streams.
- **Dynamic port allocation**: Use non-predictable RTP port ranges to make targeted flooding more difficult.
- **QoS policies**: Implement DiffServ QoS markings for VoIP traffic to prioritize legitimate RTP over flood traffic.
- **Bandwidth limiting**: Apply per-flow bandwidth limits that match expected codec requirements (e.g., 100 kbps per RTP stream).

### Network-Level Defenses

- **VLAN isolation**: Keep VoIP on dedicated VLANs with strict access control lists preventing unauthorized access.
- **Ingress filtering**: Block spoofed source IP packets at the network edge (BCP 38).
- **Anomaly detection**: Deploy network monitoring that alerts on unusual traffic volumes to VoIP infrastructure.
- **Redundancy**: Design VoIP infrastructure with failover capabilities so secondary servers can absorb traffic during attacks.

### Monitoring and Alerting

- Monitor SIP registration and INVITE rates per source IP.
- Alert when SIP message rates exceed 2x the historical baseline.
- Track call setup failure rates and alert on spikes.
- Monitor RTP stream quality metrics (jitter, packet loss, latency).
- Log all SIP 429 (Give Consent) and 503 (Service Unavailable) responses as potential DoS indicators.

---

## Key Takeaways

1. VoIP DoS attacks are highly effective because real-time voice communication is sensitive to even small disruptions.
2. Always obtain explicit written authorization before DoS testing, and scope the maximum intensity.
3. Start with low-volume floods and increment gradually — you are measuring resilience, not trying to crash the system.
4. Test each vector independently before combining them to isolate impact per protocol.
5. Document recovery time — this is critical for the client's incident response planning.
6. Recommend specific countermeasures (SBCs, rate limiting, QoS) rather than generic advice.
7. IAX2 flooding only applies to Asterisk deployments — verify the target platform first.
8. Verify full service recovery after each test phase before proceeding to the next.
