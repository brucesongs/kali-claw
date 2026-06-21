# P2PE Hardware Assessment Playbook

> Deep-dive companion to `skills/payment-security/SKILL.md` and `guides/payment-pentest-playbook.md`.
>
> Audience: payment-security assessors and QSA-adjacent engineers who already know what PCI-DSS is and want a battle-tested playbook for assessing Point-to-Point Encryption (P2PE) solutions — the HSM-backed cryptographic envelopes that take cardholder data from the PIN pad to the processor without ever exposing it in cleartext on the merchant network.
>
> Scope: P2PE solution architecture, Hardware Security Module (HSM) assessment, PIN Entry Device (PED) testing, key injection procedures, the PCI P2PE standard, terminal tamper testing (Ingenico, Verifone, Castles), and receipt/audit-trail validation. The non-hardware payment pentest workflow is covered in `payment-pentest-playbook.md`.

---

## 1. Why a Hardware-Focused Playbook, Not Just More API Testing

A Burp scan of a payment gateway finds the easy bugs in a week. The trap is treating that scan as the deliverable. Payment systems in regulated deployments sit behind a P2PE cryptographic envelope, and the security posture of that envelope is defined by hardware, key management, and physical tamper resistance — none of which appear in HTTP traffic.

A defensible P2PE assessment produces:

1. **Architecture mapping** — every component that touches plaintext cardholder data, every cryptographic boundary crossed, every key used and where it lives.
2. **HSM validation** — the Hardware Security Module is the root of trust. Is it PCI-validated? Is it configured per vendor guidance? Are its audit logs complete and tamper-evident?
3. **PED testing** — the PIN Entry Device is the merchant-side cryptographic boundary. Is it on the PCI-approved list? Is the right firmware loaded? Does tamper response fire reliably?
4. **Key injection review** — the process by which keys are loaded onto PEDs. Who performs it, where, with what HSM, under what dual-control?
5. **Cryptographic key lifecycle** — generation, distribution, injection, rotation, decommissioning, destruction. Every key has a documented lifecycle, or it's a finding.
6. **Terminal tamper testing** — physical attempts to extract keys from PEDs (where authorized). The terminal's tamper response must zero keys before extraction succeeds.
7. **Receipt and audit trail validation** — receipts must not contain full PANs; logs must not contain PANs or track data; the paper trail must be consistent with the digital trail.

This guide walks through all seven, in order, with the exact commands, decision points, and references.

---

## 2. Pre-Flight: Scope, Authorization, and Equipment

P2PE assessments cross physical and logical boundaries that ordinary pentests don't. Resolve these before any active testing:

- **What's the solution name and version under test?** P2PE solutions are PCI-listed as named solutions (e.g., "Clover by Fiserv", "Verifone Point-to-Point Encryption", "Ingenico Telium 3"). The PCI P2PE listing defines scope — outside the listed solution is out of scope.
- **What's the hardware variant?** A PED model family (e.g., Verifone Engage) has multiple variants with different tamper-response characteristics. Confirm the specific model number, firmware version, and PCI PED listing.
- **Is physical tamper testing authorized?** Tamper testing destroys the device. Most assessments are paper-and-firmware only; physical destruction requires explicit authorization and a budget for replacement devices.
- **Is key extraction testing authorized?** Decapsulation, side-channel, fault injection — these are the realm of nation-state attackers and academic researchers. PCI P2PE assessments typically do NOT include them; they rely on the device's PCI PED evaluation as evidence of tamper resistance.
- **Who's the HSM vendor and what's the HSM model?** HSMs (Thales Luna, Entrust nShield, Utimaco, AWS CloudHSM, Azure Managed HSM) have different configuration surfaces. Pull the vendor's hardening guide before testing.
- **What's the key hierarchy?** P2PE solutions have a documented key hierarchy (master keys, key-encrypting keys, data-encrypting keys). The hierarchy should be in the vendor's P2PE documentation.
- **Is the assessment for compliance or for security?** Compliance (PCI P2PE recertification) has a defined test plan from the QSA. Security (a deeper red-team-style review) is broader but produces findings the QSA may not accept.

If any of these are unclear, stop and resolve before proceeding. Physical tamper testing without written authorization and a budget for replacements is the single most common scope escalation.

### 2.1 Equipment inventory

A serious P2PE assessment requires physical and logical equipment:

| Item | Purpose | Notes |
|------|---------|-------|
| Pedestal PED test units (3+) | Tamper, firmware, interaction testing | Do NOT use production devices; obtain dedicated test units from the vendor |
| Logic analyzer (Saleae,.scope) | Side-channel signal capture (where authorized) | Optional; typically out of scope for PCI P2PE |
| Oscilloscope | Power-glitch fault injection (where authorized) | Out of scope for PCI P2PE recertification |
| Smartcard reader (ACR38, OmniKey) | EMV L1/L2 chip testing | Standard for terminal testing |
| Magnetic stripe reader test cards | Track data testing | Vendor-supplied reference cards |
| Contactless test cards | NFC wallet, contactless EMV | Vendor-supplied reference cards |
| HSM test instance | Key injection workflow validation | Vendor dev/test instance, not production |
| Payment processor sandbox | End-to-end flow testing | Stripe, Adyen, Braintree all provide sandbox accounts |

---

## 3. P2PE Solution Architecture Review

The first deliverable is a one-page architecture diagram that shows every component, every data flow, every cryptographic boundary, and every key.

### 3.1 Canonical P2PE architecture

```
┌────────────┐    encrypted     ┌────────────┐    encrypted     ┌──────────────┐
│   PED      │ ───────────────> │  Gateway   │ ───────────────> │  Processor   │
│ (terminal) │  (P2PE envelope) │  (merchant │  (P2PE envelope │  / Acquirer  │
│            │                  │   side)    │   or re-encrypt) │              │
└────────────┘                  └────────────┘                  └──────────────┘
     │                                                               │
     │ plaintext card data exists ONLY here                          │ plaintext card data
     │                                                               │ exists again here
     ▼                                                               ▼
┌────────────┐                                               ┌──────────────┐
│   Card     │                                               │  HSM         │
│ (chip/mag/ │                                               │ (decrypt and │
│  contactless)                                              │  authorize)  │
└────────────┘                                               └──────────────┘
```

Key observations to verify:

1. **Plaintext cardholder data exists at the card, in the PED, in the processor's HSM, and nowhere else.** Anything else is a finding.
2. **The PED encrypts the card data before it leaves the device.** The cryptographic operation happens on the PED, using keys injected at provisioning.
3. **The merchant network carries only encrypted data.** Sniffing the merchant LAN should yield no usable card data.
4. **The processor's HSM decrypts inside its secure boundary.** The decryption key never leaves the HSM.
5. **Logs at every layer contain no PAN.** Verify by sampling logs.

### 3.2 Architecture review checklist

For each component in scope:

- [ ] **Vendor name, model, firmware version** documented
- [ ] **PCI listing status** — is the component on the PCI SSC list of approved PIN Entry devices / HSMs / P2PE solutions?
- [ ] **Cryptographic boundary** — where is plaintext card data present? Confirm by code review or vendor attestation.
- [ ] **Keys used** — list every key (master, KEK, DEK, key-encrypting), with algorithm, length, and storage location.
- [ ] **Key lifecycle** — generation, distribution, injection, rotation, destruction (see §7).
- [ ] **Network flows** — every protocol (TLS, proprietary), every port, every direction.
- [ ] **Logging** — what's logged, what's not, where logs go, retention period.
- [ ] **Fail-secure behavior** — what happens if the PED loses power mid-transaction? If the HSM is unreachable? If the network is partitioned?

### 3.3 Common architectural findings

- **Plaintext logging** at a debug log level — typically disabled in production but sometimes re-enabled during incident triage.
- **Plaintext card data in exception stack traces** — the gateway's error handler logs the request body, including the (encrypted) card data, but the decryption layer's error handler logs the plaintext.
- **PAN in receipts or in the merchant's order management system** — usually a misconfiguration of the gateway, not the PED.
- **TLS termination at the merchant gateway** — re-encryption for the hop to the processor is fine, but if the merchant gateway is outside the PCI P2PE solution's listed scope, the entire merchant side may be in scope.
- **HSM shared across environments** — production and test sharing a single HSM is a critical finding; test keys could decrypt production data.

---

## 4. HSM Assessment

The HSM is the root of trust. Every key that matters lives in it. HSM assessment is mostly configuration review, key ceremony observation, and log analysis — not active exploitation.

### 4.1 HSM vendors and models

| Vendor | Notable models | Notes |
|--------|----------------|-------|
| Thales (formerly Gemalto/SafeNet) | Luna Network HSM 7, Luna Cloud HSM, ProtectServer | Most common in payment; FIPS 140-3 Level 3/4 |
| Entrust (formerly nCipher) | nShield Connect XC, nShield as a Service | Strong in EU banking |
| Utimaco | SecurityServer Se Gen 2 | Common in EU and APAC |
| Atos (formerly Bull) | Trustway HSM | French banking |
| Futurex | Vectera Plus, KMES Series 3 | US payment processor common |
| AWS CloudHSM | hsm1, hsm2 | Cloud-native; FIPS 140-3 Level 3 |
| Azure Dedicated HSM | Thales Luna 7 rebranded | Cloud-native |
| Google Cloud HSM | Cloud HSM (Luna-backed) | Cloud-native |

### 4.2 Validation checklist

For each HSM in scope:

- [ ] **PCI HSM-listed** — on the PCI SSC list of approved HSMs (or FIPS 140-3 Level 3+ validated, per PCI P2PE standard requirements)
- [ ] **FIPS 140-2/140-3 validation certificate** matches the firmware/hardware version in production
- [ ] **Vendor hardening guide followed** — every required setting checked
- [ ] **M-of-N access control** enabled — quorum of HSM Officer cards required for sensitive operations (typically 2-of-3 or 3-of-5)
- [ ] **Audit logging enabled** — every cryptographic operation logged, logs tamper-evident, retention >= 1 year
- [ ] **Network segmentation** — HSM reachable only from authorized application servers, not the general merchant network
- [ ] **Backup and restore** tested — HSM contents can be backed up to an encrypted backup token, restoration tested
- [ ] **Time source** — HSM clock synchronized to a trusted NTP source; clock skew would invalidate audit timestamps

### 4.3 HSM command surface testing

HSMs expose a vendor-specific command API. Common operations: key generation, key deletion, encryption, decryption, signing, key wrapping, key import. Test:

```bash
# For Thales Luna (PKCS#11 interface)
pkcs11-tool --module /usr/safenet/lunaclient/lib/libCryptoki2.so \
            --slot 0 --login --pin <HSM_USER_PIN> \
            --list-objects

# For Entrust nShield (Hardserver)
/opt/nfast/bin/nfkminfo
/opt/nfast/bin/ncs -f                  # status check
/opt/nfast/bin/noctty -f /opt/nfast/bin/enquiry

# For AWS CloudHSM (cloudhsm-cli)
cloudhsm-cli --cluster-id <cluster> interactive
> login --username <crypto-officer> --role crypto-officer
> key list
> user list

# For generic PKCS#11
pkcs11-tool --module <module.so> --show-info
pkcs11-tool --module <module.so> -l --pin <PIN> --list-slots
pkcs11-tool --module <module.so> -l --pin <PIN> --list-mechanisms
```

Findings to look for:

- **Operator PIN complexity** — too-short PINs, shared PINs across operators, PINs in scripts.
- **Test keys marked as production** — test keys that have been used on production data.
- **Key attributes** — keys marked as `CKA_EXTRACTABLE=true` when they should not be; keys missing `CKA_SENSITIVE=true`.
- **Excessive operator accounts** — operators who have left the team but still have HSM access.
- **Disabled audit logging** — operator commands logged to `/dev/null` or never configured.

### 4.4 Key ceremony observation

HSM key generation should follow a documented ceremony. Observe (or read the ceremony log for) at least one key generation event:

- Two or more HSM Officers present (per M-of-N policy).
- Each officer inserts their card and enters their PIN.
- The ceremony is recorded in a logbook signed by all officers.
- The generated key's identifier (KID) is recorded; the key itself never appears in plaintext.
- Backup tokens (if used) are stored in a separate safe, accessed only under dual control.

Findings to look for:

- **Single-officer key generation** — bypasses M-of-N; critical finding.
- **PIN visible to other officers** — either by shoulder-surfing or by being typed while visible.
- **Backup token left in the HSM's own safe** — defeats the purpose of separate storage.
- **Ceremony log incomplete or unsigned** — chain of custody broken.

---

## 5. PED (PIN Entry Device) Testing

PEDs are the merchant-side cryptographic boundary. PCI SSC maintains a [list of approved PIN Entry Devices](https://www.pcisecuritystandards.org/assessors_and_solutions/approved_pin_transaction_devices) — anything not on the list is a finding.

### 5.1 PED validation checklist

For each PED in scope:

- [ ] **PCI PED listing** — model and firmware on the approved list
- [ ] **Firmware version** matches what was evaluated (firmware updates can change PCI status)
- [ ] **Tamper response tested** — opening the case, drilling, voltage glitching (where authorized) triggers tamper response
- [ ] **Tamper logs preserved** — tamper event recorded in PED non-volatile memory, retrievable via vendor tooling
- [ ] **Battery backup** functions (where applicable) — PED retains keys across power loss
- [ ] **Display prompts** — cardholder-facing prompts match PCI requirements (no full PAN displayed, masked entry fields)
- [ ] **Key injection** performed only by authorized personnel with documented dual-control (see §6)
- [ ] **Physical security** — PEDs mounted to counter where feasible; cable tampering evident; serial numbers logged

### 5.2 PED firmware analysis (where authorized)

```bash
# For Ingenico Telium 3 PEDs — vendor development tools allow firmware inspection
# (requires Ingenico developer agreement; out of scope for most PCI P2PE assessments)

# For Verifone Engage — VeriCentre Central management console allows fleet firmware inspection
# Pull firmware version and configuration:
vericentre-cli --device <serial> --get-version
vericentre-cli --device <serial> --get-config

# For Castles VEIVEX / similar Android-based terminals — ADB may be available
adb devices
adb shell getprop | grep -E '(ro.build.version|ro.product)'
adb shell dumpsys package | grep -E '(versionName|versionCode)'
```

Findings to look for:

- **Debug firmware in production** — dev/debug builds typically lack production tamper-response hardening.
- **Outdated firmware** with known vulnerabilities — Verifone and Ingenico both publish security advisories; check the firmware against the advisory list.
- **Developer mode enabled** — USB debugging, ADB access, SSH on PEDs that support it.
- **Side-loaded applications** on Android-based terminals — third-party apps that aren't on the terminal's whitelist.

### 5.3 Terminal tamper tests

Where physical tamper testing is authorized, the standard test matrix:

| Test | What it tests | Expected result |
|------|---------------|-----------------|
| Case opening (screw removal) | Mechanical tamper switches | Keys zeroed; PED displays "TAMPERED"; logs the event |
| Drilling through case | Drilling detection mesh | Same as above |
| Voltage glitch (momentary undervoltage) | Brown-out detection | Same; or PED refuses to operate until reset |
| Temperature extreme | Thermal tamper detection | Same |
| EMI / RF probe | Side-channel countermeasures | PED should not leak usable key material (verify via lab test) |
| Liquid intrusion | Liquid detection sensors | Same as case opening |

Document each test with: serial number of the device, test performed, timestamp, observed response, photo of the result. The QSA will want this as part of the assessment evidence.

For PCI P2PE recertification, tamper testing is typically performed by an accredited laboratory, not by the assessor. The assessor's role is to verify the laboratory's report and confirm the deployed PEDs match the tested configuration.

---

## 6. Key Injection Procedures

Keys must be injected into PEDs at provisioning time. This is the highest-risk operation in the P2PE lifecycle — if the injection process leaks a key, every transaction on that PED is compromised.

### 6.1 Key injection models

| Model | Description | Risk profile |
|-------|-------------|--------------|
| Factory injection | Vendor injects keys at manufacturing; PEDs shipped pre-loaded | Lowest risk; highest trust in vendor |
| Distributor injection | Authorized distributor injects keys before shipping to merchant | Medium risk; trust in distributor's HSM and procedures |
| On-site injection | Merchant injects keys using a local HSM | Highest risk; requires rigorous dual-control and a PCI-validated injection HSM |

For PCI P2PE solutions, only factory injection or distributor injection by an authorized facility is permitted for the listed solution. On-site injection by the merchant breaks the P2PE scope.

### 6.2 Key injection review checklist

- [ ] **Injection facility** PCI-validated (if third-party) or HSM PCI-validated (if factory)
- [ ] **Dual control** enforced during injection — two operators required
- [ ] **Injection HSM** audited and on the PCI HSM list
- [ ] **Transport security** — PEDs shipped from injection facility to merchant with tamper-evident packaging; serial numbers tracked end-to-end
- [ ] **Inventory management** — every PED's key injection recorded (device serial, key KID, injection timestamp, injecting operator)
- [ ] **Decommissioning** — when a PED is retired, its keys are zeroed (via tamper response or vendor tooling), and the decommissioning is logged

### 6.3 Testing the injection process

Where the assessment includes the injection facility:

```bash
# Observe a key injection event
# - Verify dual control (two operators, two HSM Officer cards)
# - Verify the PED's serial is recorded against the injected key KID
# - Verify tamper-evident packaging applied before shipping
# - Verify the injection HSM's audit log captures the event

# Pull the injection audit log (Thales Luna example)
/opt/safenet/lunaclient/bin/audit_log --slot 0 --start <timestamp> --end <timestamp>
# Cross-reference against the inventory management system
```

Findings to look for:

- **Injection without dual control** — single operator performs the entire injection; critical finding.
- **Injection HSM not PCI-validated** — or validated at the wrong firmware version.
- **Serial number gaps in the inventory** — PEDs that left the facility without recorded injection (or were injected without recorded shipment).
- **Tamper-evident packaging reused** — bags with the same serial number appearing multiple times in the inventory.
- **Decommissioned PEDs still in service** — flagged as decommissioned but still appearing in transaction logs.

---

## 7. PCI P2PE Standard Walkthrough

The PCI P2PE standard is a multi-document set maintained by PCI SSC. The relevant documents for an assessor:

| Document | Purpose |
|----------|---------|
| [PCI P2PE Standard](https://www.pcisecuritystandards.org/document_library) (current: v3.0) | The core requirements for P2PE solutions |
| [P2PE Qualified Assessor Guide](https://www.pcisecuritystandards.org/document_library) | How a P2PE QSA conducts the assessment |
| [P2PE Solution Template](https://www.pcisecuritystandards.org/document_library) | The vendor's documentation of their listed solution |
| [List of Validated P2PE Solutions](https://www.pcisecuritystandards.org/assessors_and_solutions/p2pe_solutions) | The authoritative list of currently-listed solutions |
| [List of Approved PIN Transaction Devices](https://www.pcisecuritystandards.org/assessors_and_solutions/approved_pin_transaction_devices) | PEDs that have passed PCI PED evaluation |

### 7.1 The P2PE assessment lifecycle

A P2PE solution's lifecycle:

1. **Vendor develops** the solution (PED firmware, HSM integration, key injection process, documentation).
2. **Vendor engages a P2PE QSA** for initial validation.
3. **P2PE QSA assesses** against the standard, produces a Report on Validation (ROV).
4. **PCI SSC reviews** the ROV and lists the solution.
5. **Merchants adopt** the listed solution (typically via a P2PE Integrator or Reseller).
6. **Annual revalidation** — the vendor re-engages the QSA each year to confirm the listed solution remains as validated.
7. **Change management** — any change to the listed solution (new PED model, new HSM, new key injection facility) requires re-validation.

### 7.2 Assessor's role

For a P2PE QSA assessment:

- Review the vendor's solution documentation (architecture, key hierarchy, key injection process, terminal management).
- Interview vendor personnel (engineering, operations, security).
- Observe the key injection process at the injection facility.
- Sample PEDs for firmware/tamper verification.
- Review HSM configuration and audit logs.
- Verify the solution's documentation matches what's deployed.
- Produce the Report on Validation (ROV).

For a non-QSA security assessment (deeper, but not producing an ROV):

- All of the above, plus:
- Active penetration testing of the merchant environment (out of scope for PCI P2PE but useful for security).
- Side-channel / fault injection testing of PEDs (out of scope; requires specialist equipment and authorization).
- Red-team simulation of attacks against the key injection facility.

### 7.3 Common standard-violation findings

- **Unlisted solution components** — PED or HSM not on the current PCI list.
- **Firmware mismatch** — deployed firmware differs from what was validated.
- **Key injection outside the validated facility** — typically discovered when PED serial numbers don't match injection facility records.
- **Shared keys across merchants** — a single master key used across multiple merchants defeats per-merchant key isolation.
- **Key rotation gaps** — keys past their documented rotation date still in service.
- **Logging gaps** — HSM audit log retention shorter than the standard requires (1 year minimum).
- **Operator access creep** — HSM Officers who have left the team still have credentials.

---

## 8. Terminal Tampering Tests — Vendor-Specific

Where physical tamper testing is in scope, the test matrix differs by vendor. Below are illustrative procedures for the most common vendors. **Do not perform any of these without explicit written authorization and a budget for replacement devices.**

### 8.1 Verifone (Engage, V200c, MX series)

```bash
# Connect via the vendor service port (requires Verifone service cable)
# Use Verifone's VeriCentre or VeriCentre Central management tooling
vericentre-cli --device <serial> --service-mode
> GET_TAMPER_STATUS
# Returns: tamper switch state, last tamper event timestamp, key zero flag

# Physical tests:
# 1. Remove the four screws on the underside; lift the lid
#    Expected: tamper switch opens; PED displays "TAMPERED" or
#              "DEVICE DISABLED"; keys zeroed
# 2. Reassemble; power cycle
#    Expected: PED refuses to boot normally until factory reset
#              (which confirms keys are gone)
# 3. Verify post-tamper key zero:
#    Attempt a transaction; expect it to fail at the PED's
#    cryptographic operation (cannot encrypt without keys)
```

### 8.2 Ingenico (iCT220, iCT250, iWL250, Link2500, Move2500)

```bash
# Telium 2 / Telium 3 platforms — use the vendor's Telium SDK (requires agreement)
# Or via the terminal's service menu (accessed via a service password)

# Physical tests:
# 1. Open the case (screws are typically behind the printer paper cover)
#    Expected: tamper mesh opens; PED displays "SECURITY ALERT";
#              keys zeroed; PED refuses to boot normally
# 2. Drill through the case at a typical attack location (behind the
#    crypto processor)
#    Expected: tamper mesh opens; same response as case opening
# 3. Voltage glitch: momentary undervoltage via a bench power supply
#    Expected: brown-out detector fires; same response

# Note: Ingenico's Tamper Response is hardware-level; once triggered,
# the PED must be returned to Ingenico for re-keying. There is no
# field recovery.
```

### 8.3 Castles (VEIVEX, MP series — Android-based)

```bash
# Android-based PEDs — additional attack surface via the Android stack
adb devices                              # if ADB is enabled
adb shell getprop ro.build.version.release
adb shell pm list packages | grep -v '^package:com.android'

# Physical tests:
# Same matrix as Ingenico. Castles uses a similar tamper mesh design.

# Software tests:
# - Verify SELinux is in enforcing mode
adb shell getenforce                     # should return "Enforcing"
# - Verify no sideloaded APKs
adb shell pm list packages -3            # third-party packages
# - Verify the bootloader is locked
adb shell getprop ro.boot.verifiedbootstate   # should be "green"
# - Verify no root access
adb shell su -c id                       # should fail
```

### 8.4 Square / Stripe (BBPOS-style readers)

```bash
# These are typically OEM'd from BBPOS and use a sealed, tamper-evident design
# Field tamper testing is generally not authorized by Square/Stripe;
# rely on the vendor's PCI PED evaluation

# What you CAN test:
# - Bluetooth pairing security (if wireless reader)
# - Firmware version (via the vendor app)
# - Bluetooth PIN complexity
# - Whether the reader can be paired to an unauthorized phone
```

---

## 9. Receipt & Audit Trail Validation

The transactional paper trail must match the digital trail. Receipts and audit logs are a frequent source of findings because they're easy to misconfigure.

### 9.1 Receipt requirements

Per PCI DSS requirement 3.3:

- **PAN masked** — maximum first-6/last-4 digits shown; middle digits masked
- **Expiration date** — must NOT appear on any receipt (customer or merchant copy)
- **CVV/CVC** — never stored, never printed, never logged (PCI DSS 3.4.1)
- **Track data** — never stored, never printed (PCI DSS 3.4.1)

### 9.2 Receipt sampling test

```bash
# Collect a sample of receipts from each PED in scope (customer and merchant copies)
# For each receipt:
#   - Verify PAN is masked (first-6/last-4 max)
#   - Verify expiration date is not present
#   - Verify CVV is not present
#   - Verify no track data is present
#   - Verify the transaction ID matches the gateway's transaction log
#   - Verify the timestamp matches the gateway's transaction log

# Common findings:
#   - Full PAN printed (misconfiguration; critical)
#   - Expiration date printed (legacy gateway setting; high)
#   - CVV printed (should never happen; critical — implies CVV is being stored)
#   - Mismatched transaction IDs (receipt and gateway disagree; investigate)
```

### 9.3 Audit log validation

For every component in the architecture:

```bash
# Sample audit logs from each layer
# Gateway logs:
grep -E '(PAN|card|track|CVV|CVC)' /var/log/gateway/transactions.log
# Expected: zero matches (or only matches in masked form)

# HSM audit logs:
# Pull a sample of HSM operation logs; verify:
#   - Every decrypt operation corresponds to a transaction in the gateway log
#   - No decrypt operations outside business hours (investigate)
#   - No decrypt operations for transactions that the gateway doesn't show
#     (indicates someone is using the HSM outside the normal flow)

# PED event logs:
# Vendor tooling (VeriCentre, Telium SDK) can pull PED tamper and event logs
# Verify:
#   - Tamper events correlate with known maintenance events
#   - No unexpected reboots or re-keys
#   - Firmware version history matches the expected update path
```

### 9.4 Common audit trail findings

- **PAN in plaintext logs** at debug log level — usually disabled in production but sometimes re-enabled.
- **Track data in error logs** — exception handler logs the request body including decrypted card data.
- **Missing log entries** — HSM operations that don't appear in the audit log (logging disabled for certain operations).
- **Log retention shorter than required** — PCI DSS requires 1 year minimum; some systems default to 30 days.
- **Log timestamps not synchronized** — different components' logs use different time sources, making correlation impossible.

---

## 10. Pre-Assessment Checklist

Before the assessment starts:

- [ ] Scope letter signed (vendor + merchant + assessor); physical tamper testing explicitly authorized or excluded
- [ ] Vendor's P2PE solution documentation provided (architecture, key hierarchy, key injection process)
- [ ] PCI P2PE listing of the solution confirmed current
- [ ] PED model, firmware versions listed; PCI PED listing confirmed for each
- [ ] HSM vendor, model, firmware version; PCI HSM listing and FIPS certificate confirmed
- [ ] Test PEDs (3+) provided by vendor; serial numbers recorded
- [ ] HSM test instance access arranged (with a Crypto Officer to operate it)
- [ ] Processor sandbox account provisioned (Stripe / Adyen / etc.)
- [ ] Sample receipts (customer and merchant copies) available for inspection
- [ ] Sample audit logs from each layer (gateway, HSM, PED) available for sampling
- [ ] Injection facility visit scheduled (if assessment includes key injection review)
- [ ] Equipment ready (smartcard reader, EMV test cards, contactless test cards, oscilloscope if FIA in scope)

---

## 11. Closing Checklist

Before marking the assessment complete:

- [ ] Architecture diagram produced; every component, flow, boundary, and key documented
- [ ] HSM validation complete; configuration matches vendor hardening guide; audit logs complete and tamper-evident
- [ ] PED validation complete; all PEDs on PCI list; firmware matches validated version
- [ ] Tamper response tested (where authorized); results match expected behavior
- [ ] Key injection process reviewed; dual control confirmed; inventory matches deployed PEDs
- [ ] Key lifecycle documented; rotation schedule exists and is being followed
- [ ] Receipt sampling clean — no PAN, expiration, CVV, or track data on any receipt
- [ ] Audit log sampling clean — no PAN or track data in plaintext at any layer
- [ ] Findings documented with severity (Critical / High / Medium / Low)
- [ ] Report written; executive summary, technical findings, remediation plan
- [ ] Vendor and merchant debrief scheduled
- [ ] Re-test date set for any Critical / High findings

---

## 12. References

- **PCI Security Standards Council**: [pcisecuritystandards.org](https://www.pcisecuritystandards.org)
- **PCI P2PE Standard (current: v3.0)**: [pcisecuritystandards.org/document_library](https://www.pcisecuritystandards.org/document_library)
- **PCI PTS (PIN Transaction Security)**: hardware requirements for PEDs and HSMs
- **List of Validated P2PE Solutions**: [pcisecuritystandards.org/assessors_and_solutions/p2pe_solutions](https://www.pcisecuritystandards.org/assessors_and_solutions/p2pe_solutions)
- **List of Approved PIN Transaction Devices**: [pcisecuritystandards.org/assessors_and_solutions/approved_pin_transaction_devices](https://www.pcisecuritystandards.org/assessors_and_solutions/approved_pin_transaction_devices)
- **NIST FIPS 140-3**: [csrc.nist.gov/projects/cryptographic-module-validation-program](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- **Common Criteria (ISO/IEC 15408)**: [commoncriteriaportal.org](https://www.commoncriteriaportal.org)
- **EMVCo**: [emvco.com](https://www.emvco.com) — EMV chip specification and terminal evaluation
- **Thales Luna HSM documentation**: [thalesgroup.com](https://cpl.thalesgroup.com/encryption/hardware-security-modules)
- **Entrust nShield documentation**: [entrust.com](https://www.entrust.com/lp/hsm)
- **Verifone developer resources**: [verifone.com](https://developer.verifone.com)
- **Ingenico developer resources**: [developer.ingenico.com](https://developer.ingenico.com)
- **PCI SSC Resource Hub**: [pcisecuritystandards.org/resources](https://www.pcisecuritystandards.org/resource-hub)

---

**Related files**: `../SKILL.md`, `../payloads.md`, `../test-cases.md`, `./payment-pentest-playbook.md`
**Integration**: `skills/api-security/`, `skills/mobile-security/`, `skills/hardware-security/`, `skills/crypto-attacks/`, `skills/firmware-reverse/`, `skills/digital-forensics/`, `skills/pentest-reporting/`
