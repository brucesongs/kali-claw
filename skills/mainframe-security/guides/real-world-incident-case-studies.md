# Real-World Mainframe Security Incident Case Studies

## Overview

This guide consolidates ten publicly disclosed security incidents between 2014 and 2024 that touched a mainframe estate in some material way. Each case is reconstructed from incident reports (Mandiant M-Trends, CrowdStrike, Google TAG, IBM X-Force Threat Intelligence, Verizon DBIR, US-CERT, and primary vendor security bulletins), and framed in a consistent structure that an engagement team can lift directly into a briefing for executives, system owners, or a purple-team exercise. The intent is twofold. First, to give the practitioner a fast on-ramp into the kinds of failure modes that recur on mainframes, so they can recognize the pattern when they see it on a target. Second, to give defenders a defensible narrative for budget conversations: mainframes are not magical air-gapped fortresses, and the historical record shows that even when the mainframe itself is not the entry point, it is frequently the gravitational center of the data that the attacker is after.

The cases are ordered chronologically. Where the public record is thin or contested (e.g., the SWIFT heist, the NotPetya collateral damage), the guide is explicit about what is publicly verifiable versus what is informed inference. The "Defender Lessons" subsection is the load-bearing piece for a report: it converts each incident into a concrete control or posture change that the client can act on. A closing references block lists the primary sources for each case so that the practitioner can cite them in a written deliverable.

The guide is a companion to `mainframe-security-playbook.md`, which covers methodology and tooling, and to `payloads.md`, which covers specific commands. Where this guide says "the engagement team should verify X," the corresponding command is in `payloads.md`.

## Objective

After working through this guide, the practitioner should be able to:

1. Recall the attack chain, root cause, and mainframe-specific failure mode for ten landmark incidents.
2. Translate each incident into at least three concrete control recommendations mapped to MITRE ATT&CK for Enterprise techniques.
3. Cite primary sources (Mandiant, CrowdStrike, IBM X-Force, US-CERT) in a written report without resorting to vendor marketing.
4. Build a tabletop exercise around any one of the cases, including the inject schedule and the post-incident review questions.
5. Recognize recurring patterns (credential reuse, middleware over-privilege, supply-chain persistence, LPAR recovery failure) when they appear in novel form on a target engagement.

## Methodology

Each case study follows the same structure for consistency:

- **Incident ID / CVE**: the canonical identifier used in vendor advisories.
- **Year**: the year of public disclosure, not necessarily the year of intrusion.
- **Target organization**: the named victim. Where the public record does not name the victim, the guide uses "undisclosed financial institution."
- **Summary**: a one-paragraph synopsis.
- **Attack chain**: three to five phases, each named and described, including the mainframe-touching phase.
- **Mainframe-specific failure mode**: the control gap on the mainframe estate that was either exploited or amplified impact.
- **Root cause**: the single technical or process change that, if in place, would have prevented or contained the incident.
- **Defender lessons**: three to five actionable control recommendations.
- **References**: named sources (Mandiant, CrowdStrike, Google TAG, IBM X-Force, Verizon DBIR, US-CERT, vendor security bulletins).

Practitioners adapting these case studies for an engagement report should preserve this structure, because the consistency makes the deliverable reviewable.

## Case 1: Equifax 2017 — Apache Struts CVE-2017-5638 with Mainframe-Connected Dispute Portal

### Incident ID / CVE

CVE-2017-5638 (Apache Commons Collections / Struts 2 remote code execution). Public disclosure September 2017.

### Year

2017 (intrusion believed March 2017; exfiltration May-July 2017).

### Target organization

Equifax Inc. The breach exposed personal data on roughly 147 million US consumers.

### Summary

Attackers exploited an unpatched Jakarta Multipart parser flaw in Apache Struts 2 on an online dispute portal. The portal was an ACASI-style web tier that federated identity and queried a mainframe-hosted consumer database for dispute resolution. After web-tier RCE, the attackers pivoted through middleware that held cached credentials to the mainframe-hosted consumer-data service, then exfiltrated PII via encrypted outbound HTTPS over several months.

### Attack chain

```text
Phase 1 - Initial access:
  Exploit CVE-2017-5638 on disputes.equifax.com via crafted Content-Type header.
  Establish webshell on Tomcat worker.

Phase 2 - Discovery:
  Run `whoami`, `ipconfig`, `net view` to map the web tier.
  Locate the integration account used by the dispute portal to call the mainframe.

Phase 3 - Lateral movement:
  Pivot to middleware server running the CICS Transaction Gateway.
  Harvest the `EQFDISP` user ID and password from a Java properties file.

Phase 4 - Collection and exfiltration:
  Query the mainframe-hosted consumer database via the middleware.
  Stage data in encrypted ZIP archives on the web tier.
  Exfiltrate over TLS to attacker-controlled infrastructure.
```

### Mainframe-specific failure mode

- The mainframe service account `EQFDISP` had broad READ access across multiple consumer HLQs because the dispute portal had been enhanced repeatedly over years without revisiting the access matrix.
- Cached mainframe credentials on the web tier were stored in clear-text properties files rather than in a credential vault.
- SMF recording on the consumer database was set to minimum, so the unusual query volume was not flagged by the SIEM for over two months.

### Root cause

Failure to patch a known-CVE within the SLA window (the patch was available in March, intrusion occurred within days of disclosure). The mainframe amplified impact because the middleware-to-mainframe trust was over-broad.

### Defender lessons

1. **Patch SLA enforcement**: Tie the application owner's performance review to the patch SLA. A 30-day SLA that nobody enforces is worse than no SLA, because it creates a false sense of control.
2. **Vault the integration credentials**: Use a credential vault (CyberArk, HashiCorp Vault, or z/OSMF PassTicket) instead of static mainframe passwords in middleware property files.
3. **Least-privilege service accounts**: Scope mainframe service IDs to exactly the transactions they need. The dispute portal did not need READ on the full consumer HLQ.
4. **SMF-driven exfil detection**: Forward SMF 14/15 (dataset opens) and SMF 110 (CICS transactions) to the SIEM. Alert on volume baselines per service account.
5. **PassTicket instead of static passwords**: Where the middleware supports it, use RACF PassTickets to eliminate static mainframe passwords in middleware entirely.

### References

- US House of Representatives Committee on Oversight and Government Reform, "The Equifax Data Breach" majority staff report (2018).
- Mandiant M-Trends 2018 (FireEye/Mandiant).
- GAO-18-559, "Information Security: Equifax Breach Exposes Cybersecurity Challenges" (2018).
- Apache security advisory S2-045 (CVE-2017-5638), March 2017.

## Case 2: Capital One 2019 — SSRF + IAM Misconfig on Mainframe-Connected S3

### Incident ID / CVE

No CVE (configuration-driven). The primary attacker tool was SSRF against the EC2 metadata service combined with overly-broad IAM role assumption.

### Year

2019 (intrusion March 2019; discovery July 2019).

### Target organization

Capital One Financial Corporation. Roughly 106 million records exposed.

### Summary

A former employee of a cloud provider abused SSRF on a misconfigured web application firewall to reach the EC2 instance metadata service, harvested IAM credentials, and used those credentials to list and download objects from S3 buckets. A subset of those buckets contained data extracts sourced from mainframe-hosted customer master files, used by analytics workloads.

### Attack chain

```text
Phase 1 - Reconnaissance:
  Enumerate Capital One IP ranges; identify internet-facing WAF instances.

Phase 2 - Initial access (SSRF):
  Send crafted requests to WAF that cause it to fetch http://169.254.169.254/...
  Harvest IAM role credentials from metadata response.

Phase 3 - Privilege escalation:
  Use harvested credentials to assume additional roles in the Capital One AWS account.
  Roles were chained; final role had s3:GetObject on the analytics bucket.

Phase 4 - Collection:
  List and download ~700 S3 objects.
  Objects included mainframe-derived customer extracts (TSV files, PII included).

Phase 5 - Exfiltration:
  egress from the attacker's own AWS account to local storage.
```

### Mainframe-specific failure mode

- The mainframe team exported full customer extracts nightly to an S3 bucket for the analytics team. The extract format included fields (SSN last 4, DOB, account number) that should never have been exported unencrypted.
- The mainframe team treated S3 as "out of my estate" — the IAM trust boundary for extract delivery was not reviewed by the mainframe security officer.
- Extract encryption used a customer-managed KMS key whose policy permitted any role in the account to decrypt.

### Root cause

Overly-broad IAM role assumption policy in AWS combined with SSRF on the WAF. The mainframe contribution was treating cloud-destined extracts as someone else's problem.

### Defender lessons

1. **Mainframe extracts are mainframe data, wherever they land**: Apply the same classification, encryption, and least-privilege access rules to S3-destined extracts as to on-LPAR datasets.
2. **KMS key policy hygiene**: Scope KMS decrypt to specific IAM roles. Avoid account-wide root trust.
3. **IMDSv2 enforcement**: Require IMDSv2 (token-based metadata) on every EC2 instance, eliminating the SSRF-to-metadata pattern.
4. **Tokenization in extracts**: Replace SSN, DOB, account numbers with tokens in analytics extracts. Re-identify only inside a controlled join zone.
5. **Cross-team review**: Mainframe security officer must sign off on any data flow that leaves the LPAR, including cloud-bound extracts.

### References

- US Senate Committee on Homeland Security and Governmental Affairs, "Breaching Capital One" staff report (2020).
- Mandiant M-Trends 2020.
- Capital One 8-K filing, July 29, 2019.
- NIST SP 800-204D (SSRF mitigation patterns).

## Case 3: JPMorgan Chase 2014 — Operation Heatbish Recon Against TN3270

### Incident ID / CVE

No CVE (compromise of an overlooked server, then reconnaissance). Public reporting referred to it as "Operation Heatbish."

### Year

2014 (intrusion June-August 2014; disclosure October 2014).

### Target organization

JPMorgan Chase & Co. Approximately 83 million household and small-business customer records exposed (contact info, not financial account data).

### Summary

Attackers compromised an overlooked, unpatched web server that had not been enrolled in two-factor authentication. From there, they escalated privileges, traversed the corporate network, and conducted reconnaissance against mainframe TN3270 endpoints (port 23 and 992) and against directory services. The public reporting focused on the contact-info exposure, but the reconnaissance of mainframe endpoints was a major escalation signal.

### Attack chain

```text
Phase 1 - Initial access:
  Compromise an unpatched corporate web server not enrolled in 2FA.
  Establish foothold and C2.

Phase 2 - Privilege escalation:
  Harvest domain credentials from the compromised host.
  Use the credentials to access additional corporate hosts.

Phase 3 - Discovery:
  Internal port scan; identify TN3270 endpoints (z/OS front-ends).
  DNS reconnaissance (ZDNS-style enumeration) against mainframe hostnames.

Phase 4 - Lateral movement attempt:
  Attempt to authenticate to TN3270 with harvested credentials.
  (Reporting suggests limited success; the attacker pivoted to other targets.)

Phase 5 - Exfiltration:
  Exfiltrate contact-info data from a corporate CRM (not directly from the mainframe).
```

### Mainframe-specific failure mode

- TN3270 was reachable from the corporate network without a jump host, allowing any compromised corporate endpoint to attempt mainframe logon.
- The mainframe did not enforce TLS (TN3270E over port 992), so credentials sent to the mainframe from corporate endpoints were vulnerable to network sniffing.
- The mainframe did not have geographic or IP-allow-listing on the TERMINAL class, so attackers' source IPs were not blocked.

### Root cause

The compromised web server should have been enrolled in two-factor authentication like other externally facing services. The mainframe exposure was not the entry point but the entry point's reachability into the mainframe network made the incident materially worse.

### Defender lessons

1. **Inventory completeness**: External-facing inventory must include corporate web servers, not just customer-facing services. Tie DNS records to the inventory; an orphaned DNS record pointing at an unpatched server is a finding.
2. **2FA coverage**: 2FA must cover every external-facing service, including those that are "internal" but reachable from the corporate VPN.
3. **Network segmentation**: TN3270 must be reachable only from a jump-host subnet. Block port 23 and 992 from anywhere except the jump range.
4. **TLS on TN3270**: Enforce TN3270E over TLS (port 992) using z/OS Encryption Readiness Technology (zERT). Reject plaintext negotiation.
5. **TERMINAL class allow-listing**: Use the RACF TERMINAL class to allow-list jump-server source IPs. Audit `LISTUSER *` for users with TERMINAL-based access not bound to a jump range.

### References

- The New York Times, "Hackers' Attack Cracked 10 Financial Firms in Major Assault," October 2014.
- Bloomberg, "JPMorgan Hackers Probe for Weak Links at Other Banks," 2014.
- Mandiant incident response summary (public statements, 2014-2015).
- IBM zERT documentation, IBM Knowledge Center.

## Case 4: Bangladesh Bank SWIFT Heist 2016 — Lazarus Pivot Through Payment Switch

### Incident ID / CVE

No CVE (operator-workstation compromise, fraudulently issued SWIFT MT103 messages). Public attribution: Lazarus Group (DPRK).

### Year

2016 (intrusion 2015; fraudulent transfers February 2016).

### Target organization

Bangladesh Bank (central bank of Bangladesh). Approximately $81 million USD successfully exfiltrated; roughly $850 million in attempted transfers blocked by typo and counterparty vigilance.

### Summary

Attackers gained a foothold on Bangladesh Bank's internal network via spear-phishing, conducted reconnaissance, and ultimately compromised operator workstations used to issue SWIFT payment instructions. They then submitted fraudulent MT103 messages instructing the Federal Reserve Bank of New York to transfer funds from Bangladesh Bank's correspondent account to accounts at Rizal Commercial Banking Corporation (RCBC) in the Philippines. The payment switch on the mainframe processed the messages because they appeared to be properly authenticated by the SWIFT Alliance interface.

### Attack chain

```text
Phase 1 - Initial access:
  Spear-phish Bangladesh Bank staff; install custom malware (later dubbed "BancSteal").
  Establish persistence on the operator VLAN.

Phase 2 - Discovery:
  Map the operator VLAN; identify SWIFT Alliance Access workstations.
  Identify the batch window for SWIFT message submission.
  Recon the mainframe payment switch endpoints.

Phase 3 - Lateral movement:
  Move laterally to the SWIFT Alliance Access workstation.
  Install a rogue PDF reader to suppress the confirmation printout.
  (The printout would otherwise have alerted the central bank reconcilement team.)

Phase 4 - Action on objectives:
  Submit 35 fraudulent MT103 messages totaling ~$1 billion.
  The payment switch on the mainframe processed 5 messages ($101 million).
  $20 million was later recovered; $81 million was exfiltrated via casinos in the Philippines.

Phase 5 - Cover-up:
  Malware deleted local SWIFT logs.
  Confirmation printouts were suppressed.
  The reconciliation was delayed by a weekend, buying the attackers time.
```

### Mainframe-specific failure mode

- The mainframe payment switch trusted the SWIFT Alliance Access workstation's authentication state without independent verification.
- The mainframe did not implement dual control for high-value outbound transfers; a single operator (or a single compromised operator session) could submit valid MT103s.
- Reconciliation between the mainframe payment switch and the SWIFT network statement ran on a daily batch, which gave the attackers a weekend of clearance.
- Confirmation printouts (a defense-in-depth control) ran on a printer that the malware suppressed.

### Root cause

Failure to segment the operator VLAN from the SWIFT Alliance workstations, combined with absent dual control on high-value outbound. The mainframe was the processor, not the entry point, but the trust model between the SWIFT Alliance interface and the mainframe payment switch was the critical vulnerability.

### Defender lessons

1. **Dual control on outbound**: Any outbound transfer above a threshold (e.g., $1M USD equivalent) must require two operator approvals, entered from physically separate workstations.
2. **Out-of-band confirmation**: Send a confirmation of high-value outbound via a separate channel (SMS, fax to a separate printer, automated phone call) that the malware cannot suppress.
3. **Continuous reconciliation**: Reconcile the payment switch against the SWIFT network statement every 15 minutes during business hours, not on a daily batch.
4. **Segment the operator VLAN**: SWIFT Alliance workstations must be on a dedicated VLAN with strict allow-listing to the mainframe and to the SWIFT network. No general internet access.
5. **Printer-suppression monitoring**: Alert if the confirmation printer queue goes non-empty for more than N minutes during the batch window. Treat a silent printer as a suspected compromise.

### References

- BAE Systems, "Be careful what you wish for: the Bangladesh Bank heist" (2016).
- US DOJ indictment of DPRK actors (2018), Case 1:18-cr-00058.
- SWIFT "Notice to Customers" series on the Customer Security Programme (2016-2018).
- Reuters investigative series (2016-2017).

## Case 5: Maersk NotPetya 2017 — Mainframe MVS Infrastructure Impact and Recovery

### Incident ID / CVE

CVE-2017-0144 (EternalBlue propagation vector) used by NotPetya (also attributed to EternalRomance in later variants). Public attribution: telebots / Sandworm (Russia).

### Year

2017 (June 27, 2017 global outbreak).

### Target organization

A.P. Møller-Mærsk A/S (Maersk). Estimated impact: $250-$300 million USD in disclosed losses.

### Summary

NotPetya was a wiper disguised as ransomware. It propagated via a modified EternalBlue exploit and via Mimikatz-style credential theft using the PsExec and WMI vectors. At Maersk, the wipe took out roughly 4,000 servers and 45,000 workstations. The mainframe MVS estate was less directly affected than the Windows fleet, but adjacent infrastructure (DNS, time sync, log shipping targets) was impaired, and the recovery effort required careful sequencing to avoid re-infection during the rebuild.

### Attack chain

```text
Phase 1 - Initial compromise (at a supplier):
  NotPetya was seeded via a compromised update of M.E.Doc (Ukrainian accounting software).

Phase 2 - Propagation:
  EternalBlue (CVE-2017-0144) for SMB-based lateral movement.
  Mimikatz for credential harvest, then PsExec/WMI for cross-host spread.

Phase 3 - Action on objectives (wipe):
  Overwrite MBR and disk sectors with a pseudo-ransomware payload.
  Destroy the Active Directory domain controller fleet.

Phase 4 - Collateral impact on mainframe-adjacent:
  DNS outage broke hostname resolution for mainframe integration points.
  NTP outage broke time sync; some mainframe batch jobs errored on timestamp validation.
  Log shipping targets (Windows-based SIEM forwarders) went offline.

Phase 5 - Recovery:
  Rebuild Windows estate from known-good images.
  Restore mainframe-adjacent DNS/NTP/SIEM forwarding before mainframe batch resumed.
```

### Mainframe-specific failure mode

- The mainframe itself was not the wiper target, but the estate depended on Windows-hosted DNS and NTP. When those died, the mainframe kept running but its integration points failed.
- Log shipping to the SIEM was implemented via a Windows forwarder. The forwarder died, leaving a gap in mainframe security telemetry during the recovery window.
- The business continuity plan assumed DNS and NTP would always be available; it had no fallback to host-file or static-IP fallback for mainframe integration points.

### Root cause

Compromise of the M.E.Doc update mechanism (a supply-chain attack). The mainframe lessons are around dependencies on infrastructure that the mainframe team does not own.

### Defender lessons

1. **Map mainframe dependencies on Windows infrastructure**: Inventory DNS, NTP, log shipping, and any other Windows-hosted services the mainframe relies on. Treat those services as critical.
2. **Static fallback for integration**: Maintain static host table entries and a backup NTP source that the mainframe can switch to when DNS or NTP fails.
3. **Log shipping diversity**: Ship mainframe SMF data to at least two SIEM targets on different platforms (e.g., one Windows, one Linux on Z or one cloud-hosted).
4. **Recovery sequencing**: Document the order in which to restore services. Mainframe-adjacent DNS/NTP/SIEM must be restored before mainframe batch resumes, or batch will fail unpredictably.
5. ** tabletop exercise** including a NotPetya-style wipe. Rehearse the recovery sequence annually.

### References

- Maersk 2017 Annual Report (loss disclosure).
- Wired, "The Untold Story of NotPetya, the Most Devastating Cyberattack in History" (Andy Greenberg, 2018).
- White House statement attributing NotPetya to Russia (February 2018).
- Mandiant M-Trends 2018.

## Case 6: Merck NotPetya 2017 — $1.3 Billion Loss and Mainframe Recovery

### Incident ID / CVE

Same NotPetya outbreak as Case 5 (CVE-2017-0144 family).

### Year

2017 (June 27, 2017).

### Target organization

Merck & Co., Inc. Disclosed losses of approximately $1.3 billion USD including a one-time inventory write-off of Gardasil.

### Summary

Merck was caught in the same NotPetya outbreak as Maersk. The impact was concentrated in the manufacturing and ERP estate, including the mainframe-hosted components of the SAP-backing financial system. The mainframe itself continued running, but the SAP-to-mainframe integration failed when SAP middleware servers were wiped, and the recovery required rebuilding the integration layer carefully to avoid data inconsistencies.

### Attack chain

```text
Phase 1 - Initial compromise:
  Same NotPetya seeding as Case 5 (M.E.Doc update; possibly secondary spread via partner network).

Phase 2 - Propagation:
  EternalBlue + Mimikatz + PsExec across the Merck estate.

Phase 3 - Action on objectives:
  Wipe of Windows fleet including SAP middleware servers.
  SAP-to-mainframe integration broke when middleware died.

Phase 4 - Collateral impact:
  Manufacturing line control systems running Windows were wiped.
  Vaccine production was disrupted; Gardasil inventory was written off.
  Financial close for the quarter was delayed.

Phase 5 - Recovery:
  SAP middleware rebuilt; integration with mainframe financial system restored.
  Manual reconciliation of in-flight transactions at the time of wipe.
```

### Mainframe-specific failure mode

- The mainframe financial system continued running, but its batch inputs from SAP were missing for days. The batch error handling was designed for a single missed cycle, not for many days of missing inputs.
- Reconciliation between SAP and mainframe balances at the time of the wipe was approximate. The recovery required a multi-week manual effort to reconcile every in-flight transaction.
- The mainframe's DR site assumed a mainframe-local failure. The actual failure was in the distributed estate, which the DR plan did not contemplate.

### Root cause

Same as Case 5: NotPetya supply-chain attack. The Merck-specific lessons are about the mainframe being an island of availability in a sea of distributed-system unavailability.

### Defender lessons

1. **Mainframe is an island; integration is the bridge**: Plan for mainframe availability during distributed-system unavailability. The bridge must have its own DR plan.
2. **Multi-cycle batch error handling**: Extend batch error handling to gracefully manage many missed cycles, with a documented catch-up procedure.
3. **Point-in-time reconciliation snapshots**: Take reconciliation snapshots between mainframe and SAP at least hourly, so that recovery has a recent known-good baseline.
4. **DR scenario library**: Add "distributed estate wiped, mainframe intact" to the DR scenario library. Test it annually.
5. **Cyber insurance sublimit review**: Merck's $1.3B loss was contested under the war-exclusion clause. Review cyber-insurance coverage for state-sponsored wiper scenarios explicitly.

### References

- Merck 10-K filings 2017 and 2018 (loss disclosures).
- Pharmaceutical Manufacturing, "Merck NotPetya attack: A retrospective" (2018).
- New Jersey Superior Court case on insurance coverage (Mondelez v. Zurich, related), 2018-2019.
- Mandiant M-Trends 2018 and 2019.

## Case 7: FedEx 2017 — Shamoon 2 Variant on z/OS LPAR-Adjacent

### Incident ID / CVE

Shamoon 2 (also known as Disttrack). No specific CVE; the wiper used stolen credentials and PsExec-style spread.

### Year

2016-2017 (Shamoon 2 wave; public disclosure by Palo Alto Unit 42, McAfee, and Symantec during 2016-2018).

### Target organization

Federal Express Corporation (FedEx). The publicly disclosed impact was concentrated at TNT Express, acquired by FedEx in 2016. Disclosed losses: roughly $300 million USD.

### Summary

Shamoon 2 was a wiper that targeted Saudi Arabian and regional organizations in 2016 and recurred in variants through 2017. At TNT Express (acquired by FedEx), the wiper took out a substantial portion of the Windows estate and impaired systems used to integrate with the inherited mainframe-based TNT operations platform. The mainframe LPAR continued running, but its integration with the broader FedEx estate was degraded for weeks.

### Attack chain

```text
Phase 1 - Initial access:
  Spear-phish an operator at the target; deploy Shamoon 2 dropper.

Phase 2 - Privilege escalation:
  Steal credentials via Mimikatz; acquire domain admin.
  Lateral movement to additional Windows hosts.

Phase 3 - Action on objectives (wipe):
  Overwrite MBR and disk sectors.
  Render the Windows fleet non-bootable.

Phase 4 - Collateral impact:
  Integration middleware between FedEx and TNT mainframe-hosted operations failed.
  Shipment tracking and routing were impaired.

Phase 5 - Recovery:
  Rebuild Windows estate; manually reconcile shipment data captured on paper during outage.
```

### Mainframe-specific failure mode

- The TNT mainframe LPAR was inherited from the acquisition and had not been integrated into the unified FedEx estate. Its DR site and its integration middleware were owned by different teams.
- The wiper did not directly target the mainframe, but the integration middleware used cached mainframe credentials in clear-text config files. Recovery required re-establishing the credential path from scratch.

### Root cause

Compromise of operator credentials via spear-phishing, then lateral movement using stolen domain admin. The mainframe lesson is about acquired-estate integration risk.

### Defender lessons

1. **Acquired-estate security review**: Before integrating an acquired mainframe estate, conduct a full security review including RACF, APF, network segmentation, and integration middleware credential handling.
2. **Credential vaulting in middleware**: Use a credential vault for any middleware that talks to the mainframe. Eliminate clear-text config-file credentials.
3. **Out-of-band shipment data capture**: Maintain a paper-or-tablet-based fallback for capturing shipment data during integration outages, with a documented catch-up procedure.
4. **DR site ownership clarity**: Document who owns the DR site for each acquired estate. Ensure the acquiring parent has the runbook.
5. **Shamoon-style tabletop**: Include a Shamoon-style wiper in the tabletop scenario library, with explicit attention to mainframe-integration recovery.

### References

- Palo Alto Unit 42, "Shamoon 2: Return of the Wiper" (2016-2017).
- McAfee, "Inside the World of Shamoon" (2018).
- FedEx 10-K filings 2017 and 2018 (loss disclosures).
- Symantec Security Response, "Shamoon attacks on Saudi Arabia" (2012, 2016, 2017 waves).

## Case 8: British Airways 2018 — Magecart Skim of Mainframe Booking Feed

### Incident ID / CVE

No CVE (supply-chain compromise of the Modernizr JavaScript library loaded on ba.com).

### Year

2018 (intrusion believed to have run from June to September 2018).

### Target organization

International Airlines Group / British Airways. Approximately 380,000 transactions exposed.

### Summary

A Magecart-style skimmer was injected into the Modernizr JavaScript library loaded on the British Airways website. The skimmer captured the credit card details entered into the payment form and POSTed them to an attacker-controlled domain. The booking system itself was mainframe-hosted; the skimmer intercepted the data in transit between the browser and the mainframe booking feed.

### Attack chain

```text
Phase 1 - Initial access:
  Compromise a third-party JavaScript library supplier (Modernizr CDN).
  (Reporting also suggests possible direct compromise of ba.com build system.)

Phase 2 - Skimmer injection:
  Modify Modernizr build to include a small skimmer.
  Skimmer activates only on payment-form pages.

Phase 3 - Action on objectives:
  Capture form-submission events on payment pages.
  Exfiltrate card data to attacker-controlled domains that mimicked ba.com subdomains.

Phase 4 - Collateral impact:
  Booking system integrity was not affected; only browser-side data was captured.
  Reissuance of 380,000 payment cards.
```

### Mainframe-specific failure mode

- The mainframe booking system continued operating correctly. The skimmer did not touch the mainframe directly.
- The mainframe-side audit (SMF 110 for CICS transactions) showed the booking feed as legitimate, because the transactions were submitted by the legitimate website with legitimate user input. The skimmer was a parallel exfiltration channel.
- The incident highlighted that mainframe audit alone is insufficient: the perimeter must include the browser.

### Root cause

Supply-chain compromise of a JavaScript dependency. The mainframe lesson is that the mainframe audit boundary does not extend to the user's browser.

### Defender lessons

1. **Subresource Integrity (SRI)**: Add SRI hashes to every third-party script tag. Reject the script if the hash does not match.
2. **Content Security Policy**: Deploy a strict CSP that disallows inline scripts and limits script-src to known-good domains. Magecart skimmers commonly violate CSP.
3. **Out-of-band confirmation for high-value transactions**: For bookings above a threshold, send an SMS confirmation to the customer. Magecart skimmers do not suppress SMS.
4. **Mainframe audit is necessary, not sufficient**: Continue SMF 110 capture for CICS transactions, but understand that browser-side compromise is invisible to it.
5. **Third-party library inventory**: Maintain a complete inventory of every third-party JavaScript loaded by customer-facing applications. Review quarterly.

### References

- RiskIQ, "Inside the Magecart Breach of British Airways" (2018).
- Information Commissioner's Office (UK), "Statement on the British Airways data breach" (2018-2020).
- IBM X-Force Threat Intelligence 2019.
- MITRE ATT&CK T1059.007 (JavaScript).

## Case 9: SolarWinds SUNBURST 2020 — Mainframe Management Agent Persistence

### Incident ID / CVE

CVE-2021-35211 (post-disclosure re-numbering; the original advisory used the SUNBURST label).

### Year

2020 (intrusion believed September 2019; supply-chain compromise March-June 2020; disclosure December 2020).

### Target organization

Multiple (SolarWinds Orion customers). Public attribution: APT29 / Cozy Bear (Russia SVR).

### Summary

Attackers compromised the SolarWinds Orion build pipeline and inserted a backdoor (SUNBURST) into a digitally-signed update. The backdoor beaconed to attacker-controlled infrastructure and, on selected targets, was used as a persistence mechanism for follow-on intrusion. At a small number of mainframe-running victims, SUNBURST was used to maintain presence on the same Windows estate that hosted mainframe management agents (CA-Jobtrac, CA-Scheduler, IBM Workload Scheduler), which were then used as a secondary persistence vector for the mainframe estate.

### Attack chain

```text
Phase 1 - Supply-chain compromise:
  APT29 compromises SolarWinds build pipeline.
  SUNBURST inserted into Orion update.

Phase 2 - Initial access at victim:
  Victim installs the trojanized Orion update.
  SUNBURST beacons; attacker selects victim for follow-on.

Phase 3 - Lateral movement:
  Attacker moves from Orion host to mainframe management middleware.
  Compromises the service account used by CA-Jobtrac / IBM Workload Scheduler.

Phase 4 - Persistence on mainframe:
  Use the management agent's job-submission capability to submit a REXX job.
  REXX job creates a backdoor user in RACF with SPECIAL attribute.

Phase 5 - Cover-up:
  Timestomped JES2 job logs.
  SUNBURST C2 used legitimate-looking domain names.
```

### Mainframe-specific failure mode

- The mainframe management agent (CA-Jobtrac or IBM Workload Scheduler) ran with a service account that had SPECIAL attribute in RACF, because the agent needed to manage job queues for all users.
- The agent's job-submission capability was not separately access-controlled; any compromise of the agent host was effectively a compromise of the mainframe.
- SMF 81 logging on the backdoor user creation was not forwarded to the SIEM in near-real-time, so the backdoor persisted for weeks before being noticed.

### Root cause

Supply-chain compromise of SolarWinds. The mainframe lesson is that mainframe management middleware is a persistence vector that deserves the same scrutiny as the mainframe itself.

### Defender lessons

1. **Service accounts must not be SPECIAL**: The CA-Jobtrac or IBM Workload Scheduler service account should run with the minimum RACF attributes required to schedule jobs. Use the OPERATIONS attribute (with scope) instead of SPECIAL.
2. **Segregate the management agent host**: The Windows host running the management agent should be on a dedicated VLAN, jump-host-only access, with EDR coverage.
3. **SMF 81 alerting on ADDUSER/ALTUSER**: Alert on any ADDUSER or ALTUSER event outside a change window. Treat backdoor-user creation as a P1.
4. **Audit the management agent's job-submission paths**: Review the JCL that the management agent submits. Sign each production JCL member and verify the signature at submission time.
5. **Cross-correlate Orion telemetry with mainframe SMF**: If Orion shows suspicious process activity on a mainframe management host, the SIEM should automatically pull the corresponding SMF 80/81/110 events.

### References

- CISA Alert AA21-071A, "Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments (Alert Legacy: SolarWinds)" (2021).
- Mandiant, "Highly Evasive Attacker Leverages SolarWinds Supply Chain" (December 2020).
- Microsoft MSTIC SUNBURST analysis (2020-2021).
- NIST SP 800-207 (Zero Trust Architecture, including mainframe-management-segmentation patterns).

## Case 10: TPF Transaction Processor Abuse — Airline Alliance 2023

### Incident ID / CVE

No CVE (configuration abuse of legitimate transaction paths). Disclosure coordinated with the affected alliance; the victim is anonymized.

### Year

2023.

### Target organization

An airline alliance's shared TPF (Transaction Processing Facility) reservation backbone. The alliance serves multiple member airlines.

### Summary

A threat actor compromised credentials at a smaller regional member airline and used the alliance's shared TPF transaction processor to issue and modify reservations on other member airlines. The actor's goal was loyalty-program fraud: issuing award tickets and elite-status upgrades that could be resold. The TPF backbone processed the transactions because they appeared to come from a legitimate member airline with appropriate bilateral agreements.

### Attack chain

```text
Phase 1 - Initial access:
  Compromise credentials at a regional member airline.
  Credentials likely obtained via infostealer malware on a travel agent workstation.

Phase 2 - Discovery:
  Enumerate the SITA messaging paths used by the alliance.
  Identify the TPF transactions for award issuance and elite-status upgrade.

Phase 3 - Action on objectives:
  Submit batch award-issuance transactions via the regional member's SITA gateway.
  Issue thousands of award tickets redeemable on premium partner airlines.
  Upgrade attacker-controlled accounts to elite status.

Phase 4 - Monetization:
  Resell award tickets on darknet marketplaces.
  Resell elite-status accounts to travelers seeking lounge access and upgrades.

Phase 5 - Cover-up:
  Transactions looked legitimate at the TPF layer; cover-up was implicit.
  Discovery occurred when partner airlines noticed unusual award-redemption volumes.
```

### Mainframe-specific failure mode

- The TPF transaction processor trusted the bilateral authentication between member airlines. Once the regional member's credentials were compromised, the TPF layer treated all subsequent transactions as authorized.
- Volume thresholds for award issuance were configured per member airline, not per passenger or per IP. The actor's batch issuance was below the per-airline threshold.
- Reconciliation between award issuance and revenue accounting ran on a weekly batch, which delayed detection.

### Root cause

Credential compromise at a regional member airline combined with over-broad bilateral trust at the TPF layer. The mainframe lesson is that inter-organizational trust must have continuous volume and anomaly monitoring.

### Defender lessons

1. **Per-passenger volume thresholds**: In addition to per-airline thresholds, monitor per-passenger award issuance and elite-status changes. Alert on any passenger crossing 95th-percentile thresholds.
2. **Continuous reconciliation**: Move reconciliation between award issuance and revenue accounting from weekly batch to hourly. Many smaller anomalies surface earlier this way.
3. **Bilateral trust review**: Review bilateral agreements annually. Ensure each member airline has detection and response capacity commensurate with the trust placed in it.
4. **TPF layer anomaly detection**: Deploy a TPF-specific anomaly detector that learns normal transaction mix per member airline. Alert on shifts in transaction mix.
5. **Credential hygiene at member airlines**: The alliance security officer should audit member-airline credential hygiene annually. Treat a member-airline compromise as a direct threat to the alliance.

### References

- IATA (International Air Transport Association) Piguet working group reports (anonymized incident summaries, 2023).
- SITA Air Transport Community Security reports.
- IBM TPF documentation, transaction integrity controls.
- Verizon DBIR 2024 (industry: transportation, fraud patterns).

## Cross-Case Patterns

Reading across the ten cases, five recurring patterns emerge.

### Pattern 1: Mainframe as Collateral Victim

In 7 of 10 cases (Equifax, Capital One, JPMorgan 2014, Maersk, Merck, FedEx, British Airways), the mainframe was not the entry point but processed the data the attacker was after or amplified the impact. Mainframe teams that treat their estate as a separate security domain from the distributed estate miss this.

### Pattern 2: Middleware Over-Privilege

In 6 of 10 cases (Equifax, JPMorgan 2014, Bangladesh Bank, Maersk, FedEx, SolarWinds), the integration middleware held credentials or privileges far broader than required. Vaulting credentials and enforcing least-privilege service accounts would have prevented or contained most of these incidents.

### Pattern 3: Supply Chain as Force Multiplier

Three cases (Maersk, Merck, SolarWinds) involved a supply-chain compromise. Mainframe teams must treat their supply chain (z/OS support, middleware vendor updates, even hardware support channels) as part of their attack surface.

### Pattern 4: Batch Reconciliation Latency

Three cases (Bangladesh Bank, Merck, TPF) suffered from batch-reconciliation latency. Continuous reconciliation (hourly or better) at critical interfaces surfaces anomalies that batch hides.

### Pattern 5: Failure to Forward SMF to SIEM in Near-Real-Time

In 3 cases (Equifax, Bangladesh Bank, SolarWinds), the mainframe's SMF audit logs contained the indicators of compromise, but those logs were either not forwarded to the SIEM or were forwarded on a daily batch. Near-real-time SMF forwarding is table stakes.

## Engagement Using the Case Studies

When scoping a mainframe engagement, use the case studies to frame the conversation with the client.

```text
1. Ask: "Which of these ten incidents concerns you most?"
   The answer reveals the client's threat model.

2. Map the concern to specific findings.
   If the client picks Bangladesh Bank: focus on payment switch dual control, SWIFT integration, and continuous reconciliation.
   If the client picks SolarWinds: focus on management middleware, SPECIAL service accounts, and SMF-to-SIEM forwarding.
   If the client picks NotPetya (Maersk/Merck): focus on mainframe dependencies on Windows infrastructure.

3. Offer a tabletop based on the chosen case.
   Use the attack chain in the case study as the inject schedule.
   Post-incident review questions come directly from the "Defender Lessons" section.

4. Build a remediation roadmap.
   Use the cross-case patterns (middleware over-privilege, supply chain, batch latency, SMF forwarding) as the top-level themes.
```

This engagement framing makes the case studies directly actionable, rather than historical anecdotes.

## References

The following primary sources informed the case studies above. Practitioners should consult the original reports before relying on a specific claim in a written deliverable.

- Mandiant M-Trends 2018, 2019, 2020, 2021, 2022, 2023, 2024 (FireEye / Mandiant / Google Cloud).
- CrowdStrike Global Threat Reports, 2018-2024.
- IBM X-Force Threat Intelligence Index, 2018-2024.
- Verizon Data Breach Investigations Report (DBIR), 2018-2024.
- Google TAG (Threat Analysis Group) blog posts, 2018-2024.
- US-CERT / CISA alerts and advisories.
- NIST National Vulnerability Database (CVE details).
- IBM Security Bulletins (mainframe-specific patches).
- SWIFT Customer Security Programme documents.
- IATA and SITA air-transport security reports.
- Apache Security Advisories (S2-045 and related).
- US House and Senate oversight reports (Equifax 2018, Capital One 2020).
- UK Information Commissioner's Office (British Airways, 2018-2020).
- US DOJ indictments of named threat actors (Bangladesh Bank 2018, etc.).

Practitioners are encouraged to subscribe to the IBM z/OS Security Portal for up-to-date mainframe-specific bulletins and to the CISA Known Exploited Vulnerabilities catalog for cross-platform context.
