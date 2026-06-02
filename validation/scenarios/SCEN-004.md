# SCEN-004: Mobile Attack Chain

| Field | Value |
|-------|-------|
| **ID** | SCEN-004 |
| **Name** | Mobile Application Attack Chain |
| **Type** | Attack Chain (Mobile + Wireless + Crypto) |
| **Kill Chain Phase** | Wireless Intercept → Mobile App Analysis → API Exploitation → Crypto Breaking |
| **Difficulty** | Advanced |
| **Estimated Duration** | 3-5 hours |

---

## Objective

Demonstrate a mobile-focused attack chain starting from WiFi interception of mobile traffic, through mobile application reverse engineering, API vulnerability exploitation, and cryptographic weakness analysis.

---

## Skill Chain

```
wifi-pentest → mobile-security → api-security → crypto-attacks
```

| Step | Skill Domain | Key Actions | Tools |
|------|-------------|-------------|-------|
| 1 | wifi-pentest | WiFi interception: rogue AP, traffic capture, SSL stripping | aircrack-ng, hostapd-wpe, bettercap |
| 2 | mobile-security | Mobile app analysis: APK decompilation, certificate pinning bypass, data leakage | apktool, jadx, frida, objection |
| 3 | api-security | API exploitation: endpoint discovery, auth bypass, parameter tampering | burpsuite, arjun, ffuf |
| 4 | crypto-attacks | Crypto analysis: weak TLS, hardcoded keys, certificate validation bypass | sslscan, testssl, Frida scripts |

---

## Prerequisites

- Test mobile application (own app or authorized target)
- Android emulator or test device with USB debugging enabled
- WiFi adapter supporting monitor mode and AP mode
- SSL/TLS testing tools configured

---

## Execution Steps

### Phase 1: WiFi Interception (wifi-pentest)

1. Set up monitoring: `airmon-ng start wlan0`
2. Capture handshake: `airodump-ng -c 6 --bssid TARGET wlan0mon`
3. Deploy rogue AP for traffic interception: `hostapd-wpe config.conf`
4. SSL stripping: `bettercap -T target.com -X --proxy`
5. Capture and analyze mobile application traffic patterns

### Phase 2: Mobile Application Analysis (mobile-security)

1. APK extraction and decompilation: `apktool d target.apk`
2. Source code review with jadx: `jadx -d output target.apk`
3. Identify hardcoded secrets, API keys, endpoints
4. Certificate pinning bypass: `frida -U -f com.target.app -l ssl_bypass.js`
5. Runtime manipulation: `objection -g com.target.app explore`

### Phase 3: API Security Testing (api-security)

1. Map API endpoints from decompiled code and captured traffic
2. Authentication testing: missing auth, expired tokens, weak session management
3. Parameter tampering: `arjun -u https://api.target.com/endpoint`
4. Test for IDOR on user data endpoints
5. Rate limiting and brute force protection assessment

### Phase 4: Cryptographic Analysis (crypto-attacks)

1. TLS configuration check: `testssl https://api.target.com`
2. Certificate validation analysis from mobile app
3. Hardcoded encryption keys extraction from APK
4. Test for weak cipher suites and deprecated algorithms
5. JWT token analysis: algorithm confusion, weak signing keys

---

## Verification Points

- [ ] Mobile traffic captured and analyzed over WiFi
- [ ] APK fully decompiled with all secrets extracted
- [ ] At least one API vulnerability documented with PoC
- [ ] Cryptographic weakness identified (weak TLS, hardcoded key, etc.)
- [ ] Attack chain documented with complete evidence trail

---

## Data Handoff Between Skills

| From | To | Data Format |
|------|----|-------------|
| wifi-pentest | mobile-security | Captured traffic patterns, API endpoints from network analysis |
| mobile-security | api-security | API URLs, authentication tokens, endpoint map from APK |
| mobile-security | crypto-attacks | Hardcoded keys, certificate pinning config, SSL context |
| api-security | crypto-attacks | JWT tokens, session cookies, encryption parameters |
