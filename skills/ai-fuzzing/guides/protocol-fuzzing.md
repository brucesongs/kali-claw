# Protocol Fuzzing: Deep Dive

> Companion to `skills/ai-fuzzing/SKILL.md`. This guide covers network protocol fuzzing, TLS/SSL fuzzing, custom binary protocol analysis, the BooFuzz framework, and real-world fuzzing examples.

---

## 1. Network Protocol Fuzzing

### TCP/UDP Targets

Protocol fuzzing targets the parsing logic in network services by sending malformed packets that violate the expected protocol structure. Unlike file fuzzing, protocol fuzzing must maintain connection state and respect protocol state machines.

**TCP vs UDP target considerations**:

| Aspect | TCP Target | UDP Target |
|--------|-----------|------------|
| Connection | Requires handshake (SYN/SYN-ACK/ACK) | Connectionless, send directly |
| State | Must track connection state | Stateless, each packet independent |
| Retransmission | OS handles retransmissions | No retransmission |
| Speed | Slower (connection overhead) | Faster (no handshake) |
| Tools | BooFuzz, AFL++ network mode | BooFuzz, Scapy, custom scripts |

**Identifying fuzzable protocol targets**:

```bash
# Discover network services
nmap -sV -p- target_ip

# Identify custom/unusual services
nmap -sV --version-intensity 5 target_ip
# Focus on services running on non-standard ports

# Banner grabbing for protocol identification
nc -v target_ip 9999
echo "HELP" | nc -w 3 target_ip 9999

# Capture traffic for protocol analysis
tcpdump -i any -w protocol_capture.pcap host target_ip and port 9999
# Perform normal protocol interaction while capturing
```

### State Machine Modeling

Most protocols are stateful: the valid transitions depend on the current state. Effective protocol fuzzing must model these states.

```
Example: Simple Authentication Protocol State Machine

  ┌─────────┐   CONNECT    ┌──────────┐   AUTH_OK    ┌───────────┐
  │  CLOSED │────────────>│ CONNECTED│────────────>│ AUTHED    │
  └─────────┘             └──────────┘             └───────────┘
                               │    ^                    │
                               │    │                    │
                          AUTH_FAIL  │              COMMAND
                               │    │                    │
                               v    │                    v
                          ┌──────────┐             ┌───────────┐
                          │  ERROR   │────────────>│  PROCESS  │
                          └──────────┘  RECOVER    └───────────┘
```

**State-aware fuzzing approach**:

1. Map all valid protocol states and transitions
2. For each state, identify which fields can be fuzzed
3. Fuzz transitions between states (invalid order, skip states)
4. Fuzz field values within valid states
5. Test error recovery paths

```python
# State machine definition for BooFuzz
from boofuzz import *

session = Session(
    target=Target(connection=TCPSocketConnection("target_ip", 9999))
)

# State 1: Connection + Authentication
s_initialize("CONNECT")
s_string("CONNECT", name="cmd")
s_delim(" ", name="sp1", fuzzable=True)
s_string("user", name="username", fuzzable=True)
s_delim(":", name="colon", fuzzable=True)
s_string("pass", name="password", fuzzable=True)
s_static("\r\n")

# State 2: Authenticated commands
s_initialize("COMMAND")
s_group("cmd", values=["LIST", "GET", "PUT", "DELETE"])
s_delim(" ", name="sp1", fuzzable=True)
s_string("/path", name="resource", fuzzable=True)
s_static("\r\n")

# State 3: Error recovery
s_initialize("INVALID_CMD")
s_string("INVALID", name="bad_cmd", fuzzable=True)
s_delim(" ", name="sp1", fuzzable=True)
s_string("garbage", name="arg", fuzzable=True)
s_static("\r\n")

# Define state transitions
session.connect(s_get("CONNECT"))
session.connect(s_get("CONNECT"), s_get("COMMAND"))
session.connect(s_get("COMMAND"), s_get("COMMAND"))       # Loop back
session.connect(s_get("COMMAND"), s_get("INVALID_CMD"))    # Error path
session.connect(s_get("INVALID_CMD"), s_get("COMMAND"))    # Recovery

session.fuzz()
```

---

## 2. TLS/SSL Implementation Fuzzing

### Certificate Fuzzing

TLS implementations parse certificates (X.509) during the handshake. Malformed certificates can trigger parsing vulnerabilities.

```bash
# Generate malformed certificates with OpenSSL
# Normal certificate (baseline)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=test"

# Fuzz certificate fields
# 1. Oversized Common Name
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert_cn_overflow.pem \
  -days 365 -nodes -subj "/CN=$(python3 -c 'print("A"*10000)')"

# 2. Expired certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert_expired.pem \
  -days -1 -nodes -subj "/CN=test"

# 3. Invalid signature algorithm
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert_weak.pem \
  -days 365 -nodes -subj "/CN=test" -md5

# Fuzz TLS server with malformed certificates
# Using openssl s_client with crafted certs
for cert in cert_*.pem; do
  echo "=== Testing: $cert ==="
  openssl s_client -connect target:443 -cert "$cert" -key key.pem \
    -CAfile "$cert" 2>&1 | head -20
done
```

### Handshake Manipulation

```python
#!/usr/bin/env python3
"""TLS handshake fuzzer using Scapy"""
from scapy.all import *
from scapy.layers.tls import *

def fuzz_tls_handshake(target_ip, target_port):
    """Fuzz TLS ClientHello variations"""
    fuzz_fields = {
        'version': [0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0000, 0xFFFF],
        'cipher_suites': [
            [0x00FF],           # No cipher
            [0x002F],           # TLS_RSA_WITH_AES_128_CBC_SHA
            [0xFFFF],           # Invalid cipher
            [0x0000],           # Null cipher
        ],
        'compression': [
            [0x00],             # No compression
            [0xFF],             # Invalid compression
        ],
    }

    for version in fuzz_fields['version']:
        # Construct modified ClientHello
        # Send and observe response
        pass  # Implementation depends on specific TLS library

if __name__ == "__main__":
    fuzz_tls_handshake("target_ip", 443)
```

### TLS Fuzzing with AFL++

```bash
# Fuzz OpenSSL with AFL++
# Build OpenSSL with AFL++ instrumentation
CC=afl-clang-fast ./config
CC=afl-clang-fast make -j$(nproc)

# Create harness for certificate parsing
cat > x509_harness.c << 'EOF'
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);
    fclose(f);

    // Parse as X.509 certificate
    const unsigned char *p = buf;
    X509 *cert = d2i_X509(NULL, &p, len);
    if (cert) {
        X509_free(cert);
    }
    free(buf);
    return 0;
}
EOF

afl-clang-fast -o x509_fuzz x509_harness.c -lssl -lcrypto -fsanitize=address
afl-fuzz -i certs_corpus/ -o findings/ -m none -- ./x509_fuzz @@
```

---

## 3. Custom Binary Protocol Analysis

### Reverse Engineering Protocol Structure

When faced with an unknown binary protocol, systematically reverse engineer its structure before building a fuzzer.

**Step-by-step approach**:

1. **Capture multiple valid exchanges** in different scenarios
2. **Identify fixed fields** (magic bytes, version numbers)
3. **Identify variable fields** (lengths, payloads)
4. **Detect checksum/CRC** (fields that change when data changes)
5. **Map state transitions** (request/response patterns)

```bash
# Step 1: Capture traffic
tcpdump -i any -w proto.pcap host target and port 9999
# Perform various operations: connect, authenticate, command1, command2, disconnect

# Step 2: Hex dump comparison
xxd exchange1.bin > ex1.hex
xxd exchange2.bin > ex2.hex
diff ex1.hex ex2.hex
# Fixed bytes appear identical; variable bytes differ

# Step 3: Analyze with Wireshark
wireshark proto.pcap
# Use "Decode As" to apply custom protocol dissector
# Use "Follow TCP Stream" to see full exchanges

# Step 4: Identify structure with radare2
r2 -c 'px 128' -q capture.bin
# Look for repeating patterns, length fields, delimiters
```

**Protocol structure identification checklist**:

```
Protocol Structure Elements to Identify:

[ ] Magic bytes / Signature
    - Fixed value at start of every packet
    - Length: typically 2-8 bytes

[ ] Version field
    - Usually 1-2 bytes after magic
    - Changes between protocol versions

[ ] Length field
    - Total packet length or payload length
    - Endianness: big (network) or little (x86)
    - Size: 1, 2, 4, or 8 bytes

[ ] Message type / Command ID
    - Usually 1-2 byte enum or integer
    - Determines how payload is parsed

[ ] Sequence number
    - Incrementing counter
    - Used for request/response matching

[ ] Flags / Options
    - Bitfield controlling behavior
    - Often 1-4 bytes

[ ] Payload
    - Variable length data
    - Format depends on message type

[ ] Checksum / CRC / MAC
    - Usually at end of packet
    - Covers some or all preceding bytes
```

### Building a Custom Protocol Fuzzer

```python
#!/usr/bin/env python3
"""Custom binary protocol fuzzer template"""
import socket
import struct
import random
import binascii

class ProtocolFuzzer:
    """Generic binary protocol fuzzer with structure awareness."""

    MAGIC = b'\xAA\xBB'

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def build_packet(self, cmd, payload):
        """Build a protocol packet with valid structure."""
        length = len(payload) + 4  # cmd(1) + length(2) + payload
        packet = self.MAGIC
        packet += struct.pack('>H', length)   # Length (big-endian)
        packet += struct.pack('B', cmd)       # Command byte
        packet += payload                     # Payload data
        # CRC32 checksum appended
        packet += struct.pack('>I', binascii.crc32(packet) & 0xFFFFFFFF)
        return packet

    def fuzz_length_field(self):
        """Fuzz the length field with boundary values."""
        fuzz_lengths = [0, 1, 255, 256, 65535, 65536, 0xFFFFFFFF, -1]
        for length in fuzz_lengths:
            packet = self.MAGIC
            packet += struct.pack('>H', length & 0xFFFF)
            packet += b'\x01'           # Command
            packet += b'A' * 10         # Payload
            self.send_and_monitor(packet, f"length={length}")

    def fuzz_command_field(self):
        """Fuzz the command byte."""
        for cmd in range(256):
            payload = b'test_payload'
            packet = self.MAGIC
            packet += struct.pack('>H', len(payload) + 4)
            packet += struct.pack('B', cmd)
            packet += payload
            self.send_and_monitor(packet, f"cmd=0x{cmd:02x}")

    def fuzz_payload(self):
        """Fuzz payload data with various strategies."""
        mutations = [
            b'',                                        # Empty
            b'\x00' * 1000,                             # Null bytes
            b'\xFF' * 1000,                             # Max bytes
            b'A' * 65536,                               # Large payload
            b'\x00\x01\x02\x03' * 256,                  # Pattern
            bytes(random.randint(0, 255) for _ in range(100)),  # Random
        ]
        for i, payload in enumerate(mutations):
            packet = self.build_packet(cmd=0x01, payload=payload)
            self.send_and_monitor(packet, f"mutation={i}")

    def fuzz_checksum(self):
        """Fuzz with invalid checksums."""
        valid_packet = self.build_packet(cmd=0x01, payload=b'test')
        # Flip bits in checksum
        for bit in range(32):
            corrupted = bytearray(valid_packet)
            corrupted[-4 + bit // 8] ^= (1 << (bit % 8))
            self.send_and_monitor(bytes(corrupted), f"checksum_bit={bit}")

    def send_and_monitor(self, packet, label):
        """Send packet and check if target crashed."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.host, self.port))
            s.send(packet)
            response = s.recv(4096)
            s.close()
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
            print(f"CRASH? [{label}]: {type(e).__name__}")

    def run_all(self):
        """Run all fuzzing phases."""
        print("=== Phase 1: Length field fuzzing ===")
        self.fuzz_length_field()
        print("=== Phase 2: Command field fuzzing ===")
        self.fuzz_command_field()
        print("=== Phase 3: Payload fuzzing ===")
        self.fuzz_payload()
        print("=== Phase 4: Checksum fuzzing ===")
        self.fuzz_checksum()

if __name__ == "__main__":
    fuzzer = ProtocolFuzzer("192.168.1.100", 9999)
    fuzzer.run_all()
```

---

## 4. BooFuzz Framework

### Setup and Configuration

```bash
# Install BooFuzz
pip install boofuzz

# Verify installation
python -c "import boofuzz; print(boofuzz.__version__)"

# Optional: Install with Web UI support
pip install boofuzz[web]
```

### Basic HTTP Fuzzer

```python
#!/usr/bin/env python3
"""BooFuzz HTTP fuzzer with all features"""
from boofuzz import *

def main():
    # Configure target
    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 80),
        ),
        fuzz_db_file="fuzz_results.db",   # Results database
        crash_threshold=3,                 # Retries before marking crash
        receive_data_after_each_request=True,
        check_data_received_each_request=True,
    )

    # Define HTTP GET request
    s_initialize("GET_REQUEST")
    s_group("Method", values=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
                               "PATCH", "TRACE", "CONNECT", "PROPFIND"])
    s_delim(" ", name="space1", fuzzable=False)
    s_string("/index.html", name="path", fuzzable=True)
    s_delim(" ", name="space2", fuzzable=False)
    s_string("HTTP/1.1", name="version", fuzzable=True)
    s_static("\r\n")

    s_string("Host: ", name="host_header")
    s_string("192.168.1.100", name="host_value", fuzzable=True)
    s_static("\r\n")

    s_string("User-Agent: ", name="ua_header")
    s_string("BooFuzz/1.0", name="ua_value", fuzzable=True)
    s_static("\r\n")

    s_string("Accept: ", name="accept_header")
    s_string("*/*", name="accept_value", fuzzable=True)
    s_static("\r\n")

    s_static("Connection: close\r\n")
    s_static("\r\n")

    session.connect(s_get("GET_REQUEST"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### Advanced BooFuzz: Session-Based Protocol

```python
#!/usr/bin/env python3
"""BooFuzz session-based protocol fuzzer (login + command flow)"""
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=TCPSocketConnection("192.168.1.100", 8080),
        ),
        fuzz_db_file="session_fuzz.db",
        restart_callbacks=[],  # Add restart callback for target recovery
    )

    # Step 1: Connect
    s_initialize("CONNECT")
    s_string("CONNECT", name="connect_cmd")
    s_delim(" ", fuzzable=True)
    s_string("version=1.0", name="version", fuzzable=True)
    s_static("\r\n")

    # Step 2: Login
    s_initialize("LOGIN")
    s_string("AUTH", name="auth_cmd")
    s_delim(" ", fuzzable=True)
    s_string("admin", name="username", fuzzable=True)
    s_delim(":", fuzzable=True)
    s_string("password123", name="password", fuzzable=True)
    s_static("\r\n")

    # Step 3: Execute commands (after successful login)
    s_initialize("COMMAND")
    s_group("command", values=["LIST", "GET", "SET", "DELETE", "STAT"])
    s_delim(" ", fuzzable=True)
    s_string("/resource", name="resource", fuzzable=True)
    s_delim(" ", fuzzable=True)
    s_size("data", output_format="ascii", name="data_length")
    s_static("\r\n")
    s_string("payload_data", name="data", fuzzable=True)
    s_static("\r\n")

    # Step 4: Disconnect
    s_initialize("QUIT")
    s_string("QUIT", name="quit_cmd")
    s_static("\r\n")

    # Define state machine transitions
    session.connect(s_get("CONNECT"))                          # Start with CONNECT
    session.connect(s_get("CONNECT"), s_get("LOGIN"))         # CONNECT -> LOGIN
    session.connect(s_get("LOGIN"), s_get("COMMAND"))         # LOGIN -> COMMAND
    session.connect(s_get("COMMAND"), s_get("COMMAND"))       # COMMAND -> COMMAND (loop)
    session.connect(s_get("COMMAND"), s_get("QUIT"))          # COMMAND -> QUIT

    # Also fuzz out-of-order transitions
    session.connect(s_get("CONNECT"), s_get("COMMAND"))       # Skip LOGIN
    session.connect(s_get("LOGIN"), s_get("QUIT"))            # Skip COMMAND

    session.fuzz()

if __name__ == "__main__":
    main()
```

### BooFuzz Results Analysis

```bash
# BooFuzz stores results in SQLite database
sqlite3 fuzz_results.db

# Query crash results
sqlite3 fuzz_results.db \
  "SELECT step_num, test_case_id, crash FROM fuzz_results WHERE crash IS NOT NULL"

# Export crash test cases for replay
sqlite3 fuzz_results.db \
  "SELECT test_case_id FROM fuzz_results WHERE crash IS NOT NULL" | \
  while read id; do
    echo "Crash test case: $id"
  done
```

---

## 5. Real-World Examples

### SSH Server Fuzzing

```bash
# Method 1: libFuzzer harness for SSH key exchange
cat > ssh_kex_harness.c << 'EOF'
#include <stdint.h>
#include <stddef.h>

// Link against OpenSSH or libssh parsing functions
extern int ssh_packet_parse(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return 0;  // Minimum SSH packet size
    ssh_packet_parse(data, size);
    return 0;
}
EOF

clang -fsanitize=fuzzer,address \
  -o ssh_kex_fuzz ssh_kex_harness.c \
  -I/usr/include/libssh -lssh

# Create corpus from captured SSH traffic
tcpdump -i any -w ssh.pcap port 22
# Extract SSH packet payloads from capture
python3 extract_ssh_packets.py ssh.pcap corpus/

./ssh_kex_fuzz corpus/

# Method 2: BooFuzz SSH handshake fuzzer
python3 ssh_boofuzz.py
```

### HTTP Parser Fuzzing

```bash
# Fuzz HTTP parser with libFuzzer
cat > http_parser_harness.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include "http_parser.h"  // From nodejs/http-parser or nghttp2

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    http_parser parser;
    http_parser_init(&parser, HTTP_REQUEST);
    http_parser_execute(&parser, &parser_settings, (const char *)data, size);
    return 0;
}
EOF

clang -fsanitize=fuzzer,address \
  -o http_fuzz http_parser_harness.c http_parser.c

# Create corpus from HTTP samples
cat > corpus/get_request << 'EOF'
GET / HTTP/1.1
Host: example.com

EOF

cat > corpus/post_request << 'EOF'
POST /api HTTP/1.1
Host: example.com
Content-Length: 13

{"key":"value"}
EOF

./http_fuzz corpus/ -max_len=65536 -timeout=10
```

### DNS Resolver Fuzzing

```bash
# Fuzz DNS response parser
cat > dns_harness.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <arpa/nameser.h>

extern int dns_parse_response(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;  // Minimum DNS header size
    dns_parse_response(data, size);
    return 0;
}
EOF

clang -fsanitize=fuzzer,address \
  -o dns_fuzz dns_harness.c dns_parser.c

# Create corpus from real DNS responses
dig @8.8.8.8 example.com A +dnssec > /dev/null
tcpdump -i any -w dns.pcap port 53
python3 extract_dns_responses.py dns.pcap corpus/

./dns_fuzz corpus/

# Fuzz with AFL++ for comparison
afl-clang-fast -o dns_fuzz_afl dns_harness.c dns_parser.c -fsanitize=address
afl-fuzz -i corpus/ -o findings/ -m none -- ./dns_fuzz_afl @@
```

### Common Protocol Fuzzing Patterns

```
Protocol Fuzzing Strategy Summary:

┌────────────────────────────────────────────────────────┐
│                   Protocol Type                        │
├──────────────┬──────────────┬─────────────────────────┤
│ Text-based   │ Binary       │ Encrypted               │
│ (HTTP, FTP,  │ (Custom,     │ (TLS, SSH,              │
│  SMTP, IRC)  │  game, IoT)  │  DTLS)                  │
├──────────────┼──────────────┼─────────────────────────┤
│ Fuzz delims  │ Fuzz magic   │ Fuzz before encryption  │
│ Fuzz commands│ Fuzz lengths │ Fuzz cert parsing       │
│ Fuzz headers │ Fuzz cmd IDs │ Fuzz handshake          │
│ Fuzz body    │ Fuzz checksum│ Fuzz key exchange       │
│              │ Fuzz padding │ Test cipher suites      │
├──────────────┼──────────────┼─────────────────────────┤
│ Tools:       │ Tools:       │ Tools:                  │
│ BooFuzz     │ BooFuzz     │ AFL++ (cert fuzzing)    │
│ wfuzz       │ Custom      │ libFuzzer (parsing)     │
│ Burp Suite  │ AFL++       │ OpenSSL test suite      │
└──────────────┴──────────────┴─────────────────────────┘
```
