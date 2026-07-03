# Coordinated Vulnerability Disclosure for Vehicles — A Practical Guide

> Companion to `real-world-incident-case-studies.md`. This guide covers the **CVD process** for vehicle security research, from initial contact through public release.

---

## Overview

The vehicle security community has spent a decade building a workable CVD framework. The landmark document is **I Am The Cavalry's Coordinated Disclosure for Connected Vehicles** (2015, revised 2020). All major OEM PSIRTs operate within this framework now, but the details vary. This guide is the practical step-by-step.

---

## Objective

You found a vehicle security bug. You want to do the right thing. This guide tells you what "the right thing" looks like in 2026.

---

## The Disclosure Window

I Am The Cavalry standard: **90 days minimum** from initial PSIRT contact to public release. Extensions possible if:

- The fix requires hardware change (longer lead time).
- The fix requires dealer visit (longer rollout).
- Multiple OEMs affected (cross-vendor coordination via Auto-ISAC).

In practice, vehicle CVDs run 90 days to 14 months. Examples:

- Jeep Cherokee 2015: 9 months (Miller/Valasek).
- BMW 14-bug 2018: 9 months (Keen Lab).
- Mercedes E-Class 2024: 14 months (Cybelline).
- Tesla Model X 2019 PEPS: ~3 months (Regulus).
- Nissan Leaf 2016 API: ~3 weeks (forced by Hunt).

---

## Step-by-Step Process

### Step 1 — Document the Finding

Before any disclosure, prepare a **Finding Report** with:

1. **Affected vehicle** (year, make, model, trim, region).
2. **Affected ECU / component** (part number, firmware version).
3. **Attack surface** (OBD-II / RF / IVI / TCU / cloud API / etc.).
4. **Prerequisites** (physical access, location, special equipment).
5. **Reproduction steps** (numbered, repeatable).
6. **Real-world impact** (drivetrain / brake / unlock / etc.).
7. **Safety implications** (could this cause injury at speed?).
8. **Suggested remediation** (gateway ACL, SecOC, key rotation).
9. **MITRE ATT&CK mapping**.
10. **Your contact info and disclosure preferences**.

### Step 2 — Identify the OEM PSIRT

Look up the OEM's official PSIRT contact:

| OEM | PSIRT Contact |
|-----|---------------|
| Tesla | `security@tesla.com` / bugbounty.tesla.com |
| Stellantis (FCA) | `bugbounty@stellantis.com` |
| Ford | `psirt@ford.com` |
| GM | hackerone.com/gm |
| BMW | hackerone.com/bmw |
| Mercedes-Benz | `psirt@mercedes-benz.com` (private) |
| VW Group | `psirt@volkswagen.de` |
| Toyota | bugbounty.toyota.co.jp |
| Honda | `psirt@hna.honda.com` |
| Hyundai / Kia | security@hyundai.com |
| Nissan | `psirt@nissanusa.com` |

If the OEM has no listed PSIRT, contact via:

- **Auto-ISAC** (`reports@autoisac.com`) — they route.
- **CERT/CC** (`cert@cert.org`) — US national coordinator.
- **IENOPA** (EU), **JPCERT/CC** (Japan) — regional.

### Step 3 — Initial Contact (Day 0)

Send a brief encrypted email:

```
Subject: Coordinated Vulnerability Disclosure — [OEM] [Affected Component]

Body:
I have identified a potential security vulnerability affecting [vehicle/component].
I would like to coordinate disclosure per I Am The Cavalry framework.

Please confirm receipt and provide:
1. PGP key for encrypted communication.
2. Secure file-upload location for the detailed report.
3. Point of contact (name, role, timezone).

I commit to:
- 90-day minimum embargo from your acknowledgment.
- No public disclosure before coordinated date.
- Auto-ISAC coordination if other OEMs are affected.

If I do not receive acknowledgment within 7 business days, I will escalate via CERT/CC and Auto-ISAC.

— [Your name and PGP fingerprint]
```

**Always use PGP.** Generate a keypair if you don't have one. Never send the Finding Report unencrypted.

### Step 4 — Coordinate (Day 1 to Day 30)

Once the PSIRT acknowledges:

- Send the encrypted Finding Report.
- Expect initial technical questions within 2 weeks.
- Provide a video demonstration if requested.
- Be available for a technical call (typically 1-2 hours).

The PSIRT will assign a CVE (or equivalent internal ID) and confirm or contest the finding. Contesting is normal — be prepared to defend your reproduction steps.

### Step 5 — Validation and Fix Window (Day 30 to Day 90)

The PSIRT will validate, often with their own team reproducing your work. Validation typically takes 2-8 weeks.

Once validated, they propose a remediation plan:

- **OTA patch** — fastest, 2-6 weeks to roll out.
- **Dealer-only flash** — slower, 8-16 weeks (dealer appointment required).
- **Hardware recall** — slowest, 6-18 months (NHTSA recall paperwork).

You and the PSIRT agree on a **public disclosure date** that gives the fix time to roll out. For OTA: 60 days post-OTA-start. For dealer: 120 days post-dealer-notification. For recall: typically the recall announcement date.

### Step 6 — Public Disclosure

Joint announcement preferred. Format:

1. **OEM advisory** with CVE, affected VINs, remediation steps for owners.
2. **Researcher blog** with technical detail, demonstration video.
3. **Press** coordinated via the OEM PR or your own.
4. **Conference talk** at DEF CON, Black Hat, etc.

Do not release exploit code on Day 0. Release a write-up that lets others reproduce the *approach* without giving them the *attack*. Wait 30+ days after public disclosure for any PoC release.

### Step 7 — Follow-up

- Submit the case to **MITRE ATT&CK for ICS** mapping repository.
- Submit DBC findings to **Auto-ISAC** shared threat library.
- Present at **DEF CON CHV** or **Black Hat Automotive**.
- Encourage the OEM to publish a post-mortem.

---

## Special Considerations

### Safety-Critical Findings

If the bug could cause injury (steering/brake at speed, airbag, etc.):

- **Contact OEM PSIRT immediately** (encrypted). Day 0, not Day 7.
- **Contact NHTSA Office of Defects Investigation** in parallel (USA): `vehiclehistory@nhtsa.dot.gov`.
- **Do not test on public roads** with other vehicles nearby.
- **Stop all active testing** while OEM validates.

### Cross-OEM Findings

If the bug affects multiple OEMs (e.g., a shared Tier-1 supplier component):

- **Coordinate via Auto-ISAC**, not directly with each OEM.
- Auto-ISAC runs a "CVE coordination" process similar to MITRE.
- Plan for a **coordinated multi-OEM release** — typically 6-12 months.

### Bug Bounty Programs

Most OEMs now offer bounties. Submission via the bounty program is a parallel path to direct PSIRT contact:

- **Bounty scope**: usually excludes powertrain / brake / airbag (reserved for direct CVD).
- **Bounty payouts**: $100 to $250,000 depending on severity and OEM.
- **Public bounty**: Tesla, FCA, BMW, GM. **Private (invite-only)**: Mercedes, Toyota, Honda.

If you submit via bounty, the bounty team will route to PSIRT. You'll typically get a faster acknowledgment but slower technical coordination.

---

## Disclosure Anti-Patterns

Avoid:

1. **Public disclosure without contact.** Causes recalls, lawsuits, and bad press. Burns future relationships.
2. **Selling to a broker.** Grey market buyers exist; selling to them is legal in most jurisdictions but ethically fraught.
3. **Detail release before OTA rolls out.** Copies of your PoC will be used in the wild.
4. **Going to press first.** OEM PR will treat you as hostile. Always technical PSIRT first.
5. **Demanding unrealistic timelines.** 90 days for a SecOC roll-out is impossible. Negotiate in good faith.

---

## Coordinated Disclosure Template (Markdown)

```markdown
# [CVE-YYYY-NNNNN] [Title]

## Affected Component
- **Vehicle**: [Year Make Model Trim]
- **ECU**: [Part Number], Firmware [Version]
- **Region**: [EU/US/JP/CN]

## Summary
[One-paragraph description]

## Attack Surface
[OBD-II / RF / IVI / TCU / cloud API]

## Prerequisites
- [Physical access to vehicle]
- [Special equipment: $X cost]

## Reproduction
1. [Step 1]
2. [Step 2]
...

## Impact
- [Door unlock / engine start / brake / etc.]

## Safety Analysis
[Could this cause injury? Under what conditions?]

## Remediation
- [OEM patch reference]: OTA 2024.XX or dealer TSB YY-NNN
- [Compensating control]: [e.g., PIN to Drive]

## Timeline
- YYYY-MM-DD: Initial PSIRT contact
- YYYY-MM-DD: Acknowledgment
- YYYY-MM-DD: Fix available (OTA / dealer)
- YYYY-MM-DD: Public disclosure (this document)

## Credits
[Researcher name and affiliation]

## References
[Link to OEM advisory, demo video, related CVEs]
```

---

## Hands-on Practice

Pick a synthetic vulnerability (e.g., "D-Bus service executes shell as root on a hypothetical head unit") and draft:

1. A complete Finding Report.
2. Initial contact email.
3. Coordinated disclosure template (filled).

Submit to your team's CVD review board (if your team has one) or post on the I Am The Cavalry Slack for peer review.

---

## References

- **I Am The Cavalry**: *Coordinated Disclosure for Connected Vehicles*, 2015 (revised 2020). `iamthecavalry.org/disclosure`
- **Auto-ISAC**: *Automotive Cybersecurity Best Practices*. `autoisac.com/best-practices`
- **ISO/SAE 21434**: Section 8.3 (Vulnerability Management).
- **UNECE R155/R156**: CSMS / SUMS regulatory framework.
- **FIRST.org**: PSIRT services framework (for OEM PSIRT maturity evaluation).

### Books and Papers

- *Coordinated Vulnerability Disclosure: A Brief History* — Allen Householder, CERT/CC.
- *The Jeep Hack Revisited: Lessons for CVD* — Miller & Valasek retrospective, 2020.

### Slides and Talks

- DEF CON CHV 2017: "How to Talk to OEMs" panel.
- Black Hat 2018: "Five Years of Auto CVD" keynote.
- RSA 2022: "Auto-ISAC at 7: What Worked".

---

## See Also

- `real-world-incident-case-studies.md` — 10 actual CVDs with timelines
- `automotive-vehicle-security-playbook.md` — engagement scope and ethics
- `quick-reference-card.md` — PSIRT contact table
