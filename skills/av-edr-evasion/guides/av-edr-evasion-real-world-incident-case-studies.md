# AV/EDR Evasion: Real-World Incident Case Studies

## Overview

Studying real-world incidents is the fastest way to understand which evasion techniques actually survive enterprise detection stacks. This guide walks through twelve notable campaigns between 2018 and 2024, each illustrating a distinct class of defender bypass: signed-binary abuse, AMSI/ETW patching, kernel driver misuse, Rust-based binary obfuscation, and living-off-the-land execution. For each case we capture the timeline, the evasion primitive, the EDR vendor response, and a red team replication path you can rehearse in a lab.

The goal is not to celebrate the attackers but to map adversary tradecraft to concrete detections and to give red teams a faithful reproduction recipe. Blue and purple teams can use the same cases to validate coverage in their own SIEM and EDR telemetry.

## Case 1: Cobalt Strike Beacon — Malleable C2 and Sleep Mask

Timeline: Cobalt Strike's Malleable C2 has been a flagship feature since version 3.x (2016). The sleep mask opcode, introduced in Cobalt Strike 4.4 (2020) and hardened in 4.7+ (2022), encrypts beacon memory while sleeping to defeat memory scanners like BeaconEye, Hunt-Sleeping-Beacons, and pe-sieve.

Evasion technique: Operators combine a custom Malleable profile (fronting legitimate domains such as CDNs), a sleep mask that XORs or RC4-encrypts the beacon's heap and thread context during `WaitForSingleObject`, and module stomping (loading the beacon into a legitimate Microsoft-signed DLL's backing section). The 4.7 release introduced timer-based sleep masks that wrap the sleep in a timer-queue APC rather than a classic thread suspension, evading thread-stack scanners.

EDR vendor response: Microsoft Defender for Endpoint added Beacon memory scanning hooks; Elastic released YARA rules for unmasked beacons in their protections repo. EDR-Rules community project maintains detection patterns for known sleep mask stubs.

Red team replication: Use a licensed Cobalt Strike 4.9+ with `sleep_mask` enabled, a custom profile derived from the `amazon` profile, and an `ArtifactKit`-derived loader that unhooked `ntdll.dll` before beacon load. Validate with pe-sieve scanning the injected process: if the scan reports no suspicious RWX private region, the sleep mask is functioning.

## Case 2: FIN7 / Carbanak Obfuscation (2018-2024)

Timeline: FIN7 (also tracked as Carbanak Sparrow) has operated since at least 2013. The Carbanak backdoor persisted across recompiles through 2024, with notable updates in 2021 (Python-based loaders) and 2023 (new C2 protocol). Mandiant and CrowdStrike published detailed analyses throughout.

Evasion technique: FIN7 consistently used digitally signed bootloader executables (forged or stolen certificates), API hashing to obscure string lookups, and custom packers over standard UPX. The 2021 Python-loader variant embedded an encrypted Python interpreter that decrypted the Carbanak DLL only after a fresh `ntdll.dll` was loaded from disk, restoring clean imports before unpacking. They also used legitimate digital signatures stolen from small businesses to pass SmartScreen and AV heuristics.

EDR vendor response: CrowdStrike and Mandiant published Indicators of Compromise including the unique C2 framing. Microsoft added AMSI inspection for the Python loader payloads.

Red team replication: Build a Python-embedded loader using `python3-webview` or `pyinstaller`, sign the final PE with a test certificate, and test against Windows Defender. Wrap the payload in a custom packer that delays unpacking until after `LoadLibrary("ntdll.dll")` triggers fresh mapping.

## Case 3: APT29 NobleBaron / FoggyWeb (2021)

Timeline: APT29 (Cozy Bear, suspected SVR-linked) used the NobleBaron single-stage loader in mid-2021 and FoggyWeb, a NOBELIUM backdoor targeting Microsoft Active Directory Federation Services, in late 2021. Microsoft published detailed reports on both.

Evasion technique: NobleBaron used a custom packing algorithm that XOR'd payload regions on top of a dynamic load configuration that varied per target. FoggyWeb hid inside the AD FS process (`Microsoft.IdentityServer.ServiceHost.exe`), a legitimate Microsoft-signed binary, effectively executing as a trusted process. FoggyWeb also used DLL search-order hijacking to load a malicious `VersionContract.dll` next to a legitimate AD FS component, defeating process-trust-based detections.

EDR vendor response: Microsoft and Mandiant published FoggyWeb detection logic looking for unusual `Microsoft.IdentityServer.ServiceHost.exe` network activity to non-Microsoft domains. EDR vendors flagged the parent-process chain anomaly.

Red team replication: In a lab AD FS server, place a malicious DLL named identically to a hijackable AD FS dependency. Use Process Monitor to confirm the load, then perform minimal C2 callback to test detection. Mandiant's blog post on FoggyWeb contains the IOCs to test against.

## Case 4: Turla GasLoad / Crutch (2020)

Timeline: Turla (suspected FSB-linked) deployed the Crutch backdoor from at least 2015 to 2019, with ESET disclosing it in January 2020. GasLoad is a more recent Turla downloader (2019-2020) that abused Dropbox for C2.

Evasion technique: Crutch ran inside `explorer.exe` via DLL hijacking, hiding behind a legitimate Microsoft-signed host. GasLoad used HTTP(S) C2 with TLS fingerprinting that mimicked legitimate Dropbox client traffic, plus filename randomization. Both relied on lightweight in-memory execution without disk artifacts.

EDR vendor response: ESET and Kaspersky published network signatures for GasLoad's Dropbox API usage patterns. Microsoft Defender flagged the Crutch DLL's known hash variants.

Red team replication: Use a `dropbox-api`-based Python downloader that mimics GasLoad's HTTP headers, executed through a reflective DLL loader inside `explorer.exe` via a known hijackable DLL name. Monitor EDR telemetry for parent-process anomalies.

## Case 5: Lazarus AppleJeus (2018-2023)

Timeline: Lazarus (North Korean, UNC4899) operated the AppleJeus campaign since 2018 targeting cryptocurrency exchanges. The 2023 variant, dubbed `TodoLoader` and `TankTracker`, was documented by Kaspersky and Recorded Future.

Evasion technique: AppleJeus masqueraded as legitimate cryptocurrency trading applications (e.g., Celas Trade Pro), signed with fraudulent certificates. The 2023 variant used multi-stage loaders with embedded encrypted payloads, the AES key derived from the infected host's hostname (ensuring the payload couldn't be decrypted off-host). They patched AMSI in memory before decrypting the final stage.

EDR vendor response: Kaspersky and AhnLab published signatures for the loader's encrypted blob format. US-CERT and FBI jointly issued alerts on North Korean crypto-targeting activity.

Red team replication: Build a fake trading app installer using Qt or Electron, embed an encrypted payload keyed to hostname, and test AMSI patch success with `AMSI_RESULT_DETECTED` checks before decrypting. Validate against a Defender-on-Server baseline.

## Case 6: Hafnium Exchange Exploitation (2021)

Timeline: Hafnium (Chinese-state-sponsored) exploited zero-day vulnerabilities in Microsoft Exchange Server (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) in March 2021. Microsoft attributed the campaign and patched in emergency out-of-band updates.

Evasion technique: Post-exploitation, Hafnium dropped China Chopper webshells disguised as legitimate ASPX files in `\inetpub\wwwroot\aspnet_client\`. The webshells executed commands in the context of the IIS worker process (`w3wp.exe`), a trusted Microsoft binary. They then used `procdump` and `ntdsutil` — both LOLBins — to dump credentials, sidestepping custom-malware detection. For persistence, they created Exchange transport rules that forwarded mail covertly, an entirely legitimate-looking configuration.

EDR vendor response: Microsoft, Volexity, and Mandiant published detection guidance looking for suspicious files in `\aspnet_client\` and abnormal `ntdsutil` invocation patterns.

Red team replication: In an Exchange lab, exploit the proxylogon chain to drop an ASPX webshell into `aspnet_client`, then use `ntdsutil` to dump `ntds.dit`. Validate that your EDR detects LOLBin misuse even though the binaries are signed.

## Case 7: BlackCat / ALPHV Rust-based Evasion (2022-2024)

Timeline: BlackCat (ALPHV) emerged in November 2021 as the first major ransomware written in Rust. Operations continued through March 2024 when the gang allegedly executed an exit scam.

Evasion technique: Rust's compiler produces verbose, hard-to-reverse binaries with extensive monomorphization, slowing static analysis. BlackCat used a configuration blob encrypted with ChaCha20, supplied via a command-line argument so the binary alone was useless. They also gathered tokens before encryption to escalate via token impersonation, and used legitimate tools (WinSCP, Rclone) for exfil. Their console-mode build used `--console` to enable verbose output, with the default build suppressing forensic breadcrumbs.

EDR vendor response: Microsoft, Trend Micro, and Palo Alto published detection logic for BlackCat's crypto routines and for misuse of WinSCP/Rclone in unusual process lineages.

Red team replication: Compile a Rust ransomware simulator using `aes-gcm` and `rand`, accept an encrypted config via CLI argument, and run in a VM lab. Validate that the binary's monomorphized functions evade signature-based detection.

## Case 8: LockBit 3.0 Anti-Analysis

Timeline: LockBit 3.0 (LockBit Black) emerged in mid-2022. The builder leaked in September 2022, spawning many spin-offs (Bl00dy, BHM, N3tw0rm) through 2024.

Evasion technique: LockBit 3.0 used a custom packing algorithm that decrypted only if the right configuration password was supplied at runtime (similar to BlackCat). It implemented extensive anti-analysis: language checks (Russian, Ukrainian exit), domain checks, GetLogicalProcessors-based sandbox detection, and Sleep-based VM evasion. It also terminated services and processes related to common EDR agents (defender, mcshield, etc.) before encryption.

EDR vendor response: CrowdStrike, Cisco Talos, and ESET published extensive write-ups. The leaked builder enabled defenders to generate variants for rule-testing.

Red team replication: Use the leaked LockBit 3.0 builder in a fully isolated lab (NEVER network-connected) to test EDR coverage. Alternatively, build a Rust/C++ simulator with the same anti-analysis stubs.

## Case 9: Volt Typhoon Living-off-the-Land (2023-2024)

Timeline: Volt Typhoon (Chinese-state-sponsored, BRONZE SILHOUETTE) was exposed by Microsoft in May 2023 targeting US critical infrastructure. Follow-up advisories from CISA, NSA, FBI, and Five Eyes partners in 2024 detailed extensive LOLBins abuse.

Evasion technique: Volt Typhoon is the canonical LOLBins-only actor. They used `nbtstat`, `netsh`, `nltest`, `wmic`, `powershell`, `net use`, `arp`, `tasklist`, `reg query`, `systeminfo`, and `Ping` — every tool a sysadmin might legitimately use — to map networks, enumerate AD, and exfiltrate via `WinRAR` to password-protected RAR archives. They also used SOHO router firmware implants (KV-Botnet) to relay traffic, blending with legitimate network flows.

EDR vendor response: CISA and Microsoft published detection guidance focused on anomalous LOLBin use patterns rather than signatures. Defenders shifted to behavioral detections like "nbtstat launched from cmd.exe spawned by wmic.exe."

Red team replication: Run a full reconnaissance pass using ONLY built-in Windows binaries (no custom tools), then review EDR alerts. The goal is to map which LOLBin patterns trigger detections in your specific stack.

## Case 10: Scattered Spider DarkGate / QakBot

Timeline: Scattered Spider (UNC3944) shifted from SIM-swap-driven access to commodity-loader deployment in 2023, partnering with DarkGate developers and operating through QakBot infections handed off by Russian gangs. Mandiant and CrowdStrike published multiple reports.

Evasion technique: DarkGate used a custom AutoIt-based loader that decrypted an embedded payload at runtime, bypassing static analysis. Scattered Spider also used legitimate remote management tools (AnyDesk, ScreenConnect, TeamViewer, Splashtop) for persistence, blending with help-desk activity. They often reset MFA enrollment and registered new devices to defeat identity-based detections.

EDR vendor response: CrowdStrike published DarkGate loader decryption tooling. Microsoft hardened Entra ID (Azure AD) conditional access anomaly detection.

Red team replication: Build an AutoIt loader with embedded encrypted payload, deploy AnyDesk in a lab, and validate EDR process lineage detection. Test conditional access blocks on new device enrollment.

## Case 11: IcedID / BumbleBee Loaders (2023)

Timeline: IcedID (BokBot) continued as a banking trojan / initial-access broker through 2023, while BumbleBee emerged in March 2022 to replace Conti's loaders, peaking in 2023 before a takedown of one infrastructure node in May 2023 (the gang remained active through 2024).

Evasion technique: IcedID used MSI packages signed with valid certificates, distributing via drive-by downloads and malspam. BumbleBee used LNK files that invoked PowerShell to load a DLL via `rundll32` with custom export names; the DLL itself was heavily obfuscated with control-flow flattening and API hashing. Both loaders unhooked `ntdll.dll` before loading the payload, restoring clean syscalls.

EDR vendor response: ESET, Proofpoint, and Google TAG published detailed unpacking and detection guidance for both loaders. Microsoft Defender added behavior-based detections for `rundll32` invoking unusual export names.

Red team replication: Build an obfuscated C++ DLL with control-flow flattening (use O-LLVM), pack with a custom packer that restores `ntdll.dll` first, and deploy via signed MSI. Validate that pe-sieve and Moneta detect the in-memory artifact.

## Case 12: BumbleBee Persistence via WMI Event Subscription

Timeline: BumbleBee added WMI-based persistence in mid-2022, documented by CrowdStrike and Red Canary's 2023 Threat Report.

Evasion technique: BumbleBee created permanent WMI event subscriptions (a `__EventFilter`, a CommandLineEventConsumer, and a binding). The consumer ran PowerShell that decrypted the next-stage payload via `System.Management.Automation` and reflected it into memory. This persistence survives user logoffs and reboots, and doesn't appear in normal autoruns checks unless explicitly scanned.

EDR vendor response: Red Canary and CrowdStrike published detections for WMI consumer creation. Microsoft Defender for Endpoint added telemetry for `__EventConsumer` creation.

Red team replication: In a lab VM, create a WMI subscription using `mofcomp` or PowerShell's `New-CimInstance` that runs an encoded PowerShell command invoking `System.Reflection.Assembly.Load`. Use `Get-WmiObject` to confirm, then validate EDR detection.

## Hands-on: Validating Your Replication

After replicating any of the above, run this validation sequence against your lab EDR:

1. Run `pe-sieve.exe /pid <PID>` from hasherezade's pe-sieve to scan the suspicious process for injected/hollowed modules.
2. Run `Moneta64.exe` from CrowdStrike's Moneta to flag any RWX private memory regions.
3. Pull EDR telemetry from the past hour for the host and review process lineage, network connections, and file modifications.
4. Confirm whether your replication triggers detections. If not, your detection stack needs work; if yes, you have a reproducible PoC.

For AMSI bypass validation, run this PowerShell one-liner (in a lab):

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

If AMSI patch succeeds, the subsequent `"Invoke-Mimikatz"` (or a test string) won't be flagged. Validate that your EDR detects the patch attempt itself.

## References

1. Cobalt Strike 4.9 release notes - HelpSystems/Fortra
2. Microsoft DART blog on FoggyWeb - https://www.microsoft.com/en-us/security/blog/2021/04/29/deepseabf-foggyweb-backdoor-deployed-through-supply-chain/
3. Mandiant FIN7 / Carbanak reports - https://www.mandiant.com/resources/blog/fin7-2-0
4. ESET Turla Crutch report - https://www.welivesecurity.com/2020/01/29/turla-crutch-keeping-back-doors-open/
5. Microsoft Volt Typhoon advisory - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
6. CISA Volt Typhoon joint advisory - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
7. Microsoft Hafnium Exchange advisory - https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
8. Palo Alto BlackCat/ALPHV analysis - https://unit42.paloaltonetworks.com/blackcat-ransomware/
9. Trend Micro BlackCat technical write-up - https://www.trendmicro.com/en_us/research/22/no/blackcat-ransomware.html
10. Red Canary 2023 Threat Report (BumbleBee) - https://redcanary.com/threat-detection-report/threats/bumblebee/
11. CrowdStrike BumbleBee analysis - https://www.crowdstrike.com/blog/bumblebee-hunting-through-the-hive/
12. Kaspersky Lazarus AppleJeus 2023 report - https://securelist.com/applejeus-lazarus-2023/110738/
13. ESET IcedID/BAZARLoader research - https://www.welivesecurity.com/
14. VX-Underground malware collection - https://www.vx-underground.org/
15. EDR-Rules community detection rules - https://github.com/elastic/protections
16. hasherezade pe-sieve - https://github.com/hasherezade/pe-sieve
17. CrowdStrike Moneta memory scanner - https://github.com/forrest-orr/moneta
