# Network Protocol Steganography Guide

## Introduction

Network protocol steganography hides secret data within the headers, timing, or payload of standard network protocols. Unlike media steganography which embeds data in files, network steganography transmits hidden information through live network traffic, making it extremely difficult to detect without deep protocol analysis. This guide covers techniques for hiding data in TCP/IP headers, ICMP packets, DNS queries, HTTP headers, and timing channels.

Network steganography exploits the inherent redundancy and flexibility in protocol specifications. Many protocol fields have unused bits, optional padding, or acceptable value ranges that can carry hidden data without triggering protocol validation. Timing channels encode information in inter-packet delays, creating a covert channel that is invisible to content-based inspection.

## Practical Steps

### 1. IP Header Idle Bits

```bash
# Encode data in IP header TOS/DSCP field using scapy
python3 -c "
from scapy.all import *

def ip_header_encode(message, dst_ip):
    '''Encode message in IP TOS field (6 usable bits per packet).'''
    binary = ''.join(format(b, '08b') for b in message.encode())
    packets = []

    for i in range(0, len(binary), 6):
        bits = binary[i:i+6].ljust(6, '0')
        tos_val = int(bits, 2)

        pkt = IP(dst=dst_ip, tos=tos_val) / ICMP()
        packets.append(pkt)

    print(f'Encoded {len(message)} chars into {len(packets)} packets')
    print(f'Payload rate: {len(message)*8/len(packets):.1f} bits/packet')
    return packets

packets = ip_header_encode('Hello', '8.8.8.8')
for i, pkt in enumerate(packets[:3]):
    print(f'  Packet {i+1}: TOS={pkt.tos} (0b{pkt.tos:06b})')
"
```

### 2. DNS Tunnel Steganography

```bash
# Hide data in DNS query subdomain labels
python3 -c "
import base64
import struct

def dns_encode(message, domain='example.com'):
    '''Encode message in DNS query subdomain labels.'''
    encoded = base64.b32encode(message.encode()).decode().rstrip('=').lower()
    # Split into DNS-label-safe chunks (max 63 chars per label)
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    queries = [f'{chunk}.{domain}' for chunk in chunks]

    print(f'Original: {message}')
    print(f'B32 encoded: {encoded}')
    for i, q in enumerate(queries):
        print(f'  Query {i+1}: {q}')
    return queries

def dns_decode(queries):
    '''Decode message from DNS query labels.'''
    labels = []
    for q in queries:
        parts = q.split('.')
        labels.append(parts[0].upper())
    combined = ''.join(labels)
    # Pad to multiple of 8 for base32
    padded = combined + '=' * (8 - len(combined) % 8) if len(combined) % 8 else combined
    return base64.b32decode(padded).decode()

queries = dns_encode('Secret data via DNS')
decoded = dns_decode(queries)
print(f'Decoded: {decoded}')
"
```

### 3. ICMP Payload Covert Channel

```bash
# Hide data in ICMP echo request payloads
python3 -c "
from scapy.all import *

def icmp_covert_send(dst_ip, message):
    '''Send hidden data in ICMP echo request payloads.'''
    packets = []
    for i, char in enumerate(message):
        # Pad ICMP payload with random bytes, embed char at specific offset
        payload = os.urandom(56)  # standard ping payload size
        payload = payload[:8] + char.encode() + payload[9:]

        pkt = IP(dst=dst_ip) / ICMP(type=8, id=0x1234, seq=i) / Raw(load=payload)
        packets.append(pkt)

    print(f'Prepared {len(packets)} ICMP packets with hidden data')
    print(f'Message: {message}')
    return packets

packets = icmp_covert_send('192.168.1.1', 'Hidden ICMP message')
"
```

### 4. TCP Timing Channel

```bash
# Encode data in inter-packet delays
python3 -c "
import time
import socket

def timing_encode(message, target_ip, target_port, base_delay=0.1):
    '''Encode binary data in TCP inter-packet timing.
    0 = base_delay, 1 = base_delay * 2'''
    binary = ''.join(format(b, '08b') for b in message.encode())

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f'Timing channel: {len(binary)} bits to transmit')
    print(f'Delay 0 (bit=0): {base_delay}s')
    print(f'Delay 1 (bit=1): {base_delay * 2}s')
    print(f'Estimated time: {len(binary) * base_delay * 1.5:.1f}s')

    for bit in binary:
        delay = base_delay * 2 if bit == '1' else base_delay
        time.sleep(delay)
        # Send probe packet
        try:
            sock.sendto(b'\\x00', (target_ip, target_port))
        except Exception:
            pass

    sock.close()
    print('Timing channel transmission complete')

print('TCP timing channel encoder ready')
"
```

### 5. HTTP Header Steganography

```bash
# Hide data in HTTP headers using custom and standard fields
python3 -c "
import requests

def http_header_encode(message, target_url):
    '''Encode message bits across multiple HTTP headers.'''
    binary = ''.join(format(b, '08b') for b in message.encode())

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept-Language': 'en-US',  # en-US=0, en-GB=1
        'Cache-Control': 'no-cache',
        'X-Request-ID': 'a1b2c3d4e5f6',  # embed in hex
    }

    # Encode in Accept-Language variations
    lang_bit = 'en-GB' if binary[0] == '1' else 'en-US'
    headers['Accept-Language'] = lang_bit

    # Encode in X-Forwarded-For IP octets
    octets = []
    for i in range(0, min(len(binary), 32), 8):
        byte_val = int(binary[i:i+8], 2)
        octets.append(str(byte_val + 1))  # avoid 0.x.x.x
    while len(octets) < 4:
        octets.append('1')
    headers['X-Forwarded-For'] = '.'.join(octets)

    print(f'Encoded {len(message)} chars in HTTP headers')
    for k, v in headers.items():
        print(f'  {k}: {v}')

http_header_encode('Test', 'https://example.com')
"
```

### 6. Packet Length Encoding

```bash
# Encode data in packet sizes
python3 -c "
from scapy.all import *

def packet_length_encode(message, dst_ip):
    '''Encode message in packet payload lengths.'''
    packets = []
    for char in message:
        # Map ASCII value to payload size (offset by 100 to avoid tiny packets)
        payload_size = ord(char) + 100
        payload = os.urandom(payload_size)

        pkt = IP(dst=dst_ip) / UDP(dport=53) / Raw(load=payload)
        packets.append(pkt)

    print(f'Encoded {len(message)} chars in {len(packets)} packets')
    for i, pkt in enumerate(packets):
        payload_len = len(pkt[Raw].load)
        original_char = chr(payload_len - 100)
        print(f'  Packet {i+1}: {payload_len} bytes -> char \"{original_char}\"')

packets = packet_length_encode('Hidden', '8.8.8.8')
"
```

## Hands-on Exercises

### Exercise 1: DNS Tunnel Setup

Configure a DNS tunnel between two hosts using custom subdomain encoding. Transmit a 1KB file through DNS queries and verify the receiver can decode it. Monitor the traffic with Wireshark and document the DNS query patterns.

### Exercise 2: Multi-Protocol Covert Channel

Build a covert channel that distributes hidden data across three different protocols (DNS, ICMP, HTTP) to reduce per-protocol detection likelihood. Implement encoding, transmission, and decoding with error correction.

## References

- RFC 791 (IP Protocol) — https://tools.ietf.org/html/rfc791
- DNS Tunneling Detection — SANS Institute Reading Room
- Covert Channels Analysis — NCSC Technical Guidance
- Steganography Techniques in Network Protocols — IEEE Survey
