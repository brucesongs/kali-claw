# VPN Attack Test Cases

## TC-VPN-001: IKE Enumeration

- **Objective**: Identify IKE service running on target and determine supported transform sets
- **Severity**: HIGH
- **Prerequisites**: Network access to target on UDP 500/4500, ike-scan installed
- **Test Steps**:
  1. Run basic IKE scan: `ike-scan -M target_ip`
  2. Check for IKE response and SA attributes
  3. Enumerate transform sets with different encryption/hash combinations
  4. Identify IKE version (v1 vs v2)
- **Expected Result**: IKE service detected with supported transforms, vendor identified via VID payloads
- **Remediation**: Disable IKE if unused, restrict IKE to known peers, update vendor software
- **Pass Criteria**: At least one IKE response received with valid SA attributes and vendor identification

## TC-VPN-002: Aggressive Mode PSK Capture

- **Objective**: Test if VPN gateway supports IKE aggressive mode to capture PSK hash for offline cracking
- **Severity**: CRITICAL
- **Prerequisites**: IKE service detected (TC-VPN-001), valid transform set identified
- **Test Steps**:
  1. Test for aggressive mode: `ike-scan --aggressive --trans='5,1,2,2' -M target_ip`
  2. If response received, capture the PSK hash
  3. Save hash for offline cracking with ikeforce or ikecrack
  4. Attempt dictionary attack on captured hash
- **Expected Result**: If aggressive mode enabled, PSK hash captured and potentially cracked revealing pre-shared key
- **Remediation**: Disable aggressive mode, use certificate-based authentication, enforce main mode only
- **Pass Criteria**: Aggressive mode vulnerability confirmed or ruled out; if vulnerable, PSK hash captured

## TC-VPN-003: IKE Transform Set Discovery

- **Objective**: Enumerate all supported IKE transform sets to identify weak algorithms
- **Severity**: MEDIUM
- **Prerequisites**: IKE service detected (TC-VPN-001)
- **Test Steps**:
  1. Test each encryption algorithm (DES=1, 3DES=5, AES=7/13)
  2. Test each hash algorithm (MD5=1, SHA1=2, SHA2=5)
  3. Test each DH group (1, 2, 5, 14, 15, 19, 20)
  4. Document all accepted transforms
- **Expected Result**: Complete list of supported transform sets with identification of weak algorithms (DES, MD5, DH group 1)
- **Remediation**: Disable weak transforms (DES, MD5, DH groups 1-5), enforce AES-256 + SHA2 + DH group 14+
- **Pass Criteria**: All supported transforms enumerated and weak algorithms flagged

## TC-VPN-004: SSL VPN Web Portal Enumeration

- **Objective**: Identify SSL VPN vendor and version, check for known vulnerabilities
- **Severity**: HIGH
- **Prerequisites**: HTTPS access to VPN portal, web browser and curl
- **Test Steps**:
  1. Identify VPN vendor from HTTP headers and page content
  2. Check for known CVEs affecting the identified version
  3. Test for default credentials
  4. Enumerate SSL/TLS configuration with testssl.sh
- **Expected Result**: VPN vendor and version identified; known vulnerabilities listed; default credential status confirmed
- **Remediation**: Update VPN software, change default credentials, harden SSL/TLS configuration
- **Pass Criteria**: Vendor identified with version; all applicable CVEs documented

## TC-VPN-005: IPSec Tunnel Testing

- **Objective**: Attempt to establish IPSec tunnel to verify configuration security
- **Severity**: MEDIUM
- **Prerequisites**: Valid or test credentials, vpnc or strongswan installed
- **Test Steps**:
  1. Configure vpnc/strongswan with test credentials
  2. Attempt tunnel establishment
  3. Verify encryption parameters of established tunnel
  4. Test for split tunneling configuration
- **Expected Result**: Tunnel establishment outcome documented with encryption parameters and routing configuration
- **Remediation**: Enforce strong encryption (AES-256, SHA2), disable split tunneling for sensitive deployments
- **Pass Criteria**: Tunnel attempt outcome documented with full configuration analysis

## TC-VPN-006: Certificate Analysis

- **Objective**: Analyze VPN certificates for security weaknesses
- **Severity**: MEDIUM
- **Prerequisites**: VPN gateway accessible on HTTPS, openssl installed
- **Test Steps**:
  1. Retrieve certificate: `openssl s_client -connect target:443`
  2. Analyze certificate chain, validity, and key strength
  3. Check for self-signed or expired certificates
  4. Verify certificate CN matches expected hostname
- **Expected Result**: Certificate analysis complete with identification of any weaknesses (expired, self-signed, weak key)
- **Remediation**: Use CA-signed certificates, enforce strong key lengths (2048+ bit RSA), implement certificate pinning
- **Pass Criteria**: Certificate chain fully analyzed with all issues documented

## TC-VPN-007: VPN Credential Brute Force

- **Objective**: Test VPN authentication for brute force resistance
- **Severity**: HIGH
- **Prerequisites**: VPN portal or IKE service accessible, common username list
- **Test Steps**:
  1. Test for account lockout policy by sending multiple failed authentications
  2. Check for rate limiting on authentication attempts
  3. Document lockout threshold and lockout duration if present
  4. Verify if failed attempt logging is enabled
- **Expected Result**: Brute force resistance assessed with lockout policy, rate limiting, and logging status documented
- **Remediation**: Implement account lockout (3-5 attempts), rate limiting, CAPTCHA, and MFA
- **Pass Criteria**: Authentication resistance fully assessed with lockout/rate limiting metrics

## TC-VPN-008: Split Tunneling Detection

- **Objective**: Verify VPN split tunneling configuration and test for traffic leakage
- **Severity**: HIGH
- **Prerequisites**: VPN client connected, tcpdump installed
- **Test Steps**:
  1. Check routing table: `ip route show`
  2. Verify all traffic routes through VPN tunnel interface
  3. Test DNS resolution through VPN vs direct
  4. Capture traffic on physical interface during VPN session
- **Expected Result**: Split tunneling status confirmed; any traffic leakage outside VPN tunnel documented
- **Remediation**: Configure full tunnel mode, disable split tunneling, enforce VPN DNS for all queries
- **Pass Criteria**: Split tunneling configuration verified with traffic capture evidence

---

## Verification Checklist

- [ ] IKE service enumerated with all supported transforms
- [ ] Aggressive mode tested and results documented
- [ ] SSL VPN portal analyzed for known vulnerabilities
- [ ] Certificate chain validated
- [ ] Authentication brute force resistance tested
- [ ] Tunnel encryption parameters verified
- [ ] Split tunneling configuration confirmed
- [ ] All findings documented with remediation recommendations
