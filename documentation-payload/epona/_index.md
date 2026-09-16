+++
title = "epona"
chapter = false
weight = 5
+++

![logo](/agents/epona/epona.svg?width=200px)
## Summary

Epona is a cross-platform native agent written in Zig. It communicates over MQTT and HTTP, supports Mythic encryption, and compiles to a small, self-contained binary with no runtime dependencies.

### Highlighted Agent Features
- Single binary, no runtime dependencies — runs on Linux, macOS, and Windows.
- Dual C2 transport: MQTT or HTTP, selected at build time via Mythic payload configuration.
- Shellcode output — Windows x86_64 PE wrapped into position-independent shellcode via donut.
- Comptime ChaCha20 string obfuscation — sensitive strings are absent from the binary in plaintext.
- Sleep obfuscation — AES keys are XOR-scrambled with an ephemeral random key during each sleep; memory scanners see garbage where keys live.
- Direct Windows syscalls — NtProtectVirtualMemory, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtOpenProcess, NtCreateThreadEx invoked via `syscall` instruction directly, bypassing EDR hooks in ntdll.
- Dynamic Win32 API loading — advapi32 and user32 functions resolved at runtime via encoded names; neither DLL appears as a static import.
- Anti-debug — Linux builds call PTRACE_TRACEME at startup; exits silently if already being traced.
- Linux sandbox detection via uptime and process-count heuristics.
- Kill timestamp — agent refuses to run after a configured date.
- Per-build entropy — a random 64-bit salt baked at compile time ensures binaries with identical config still differ on disk.
- Native API preferred for enumeration commands (no child processes for ps, netstat, getprivs, clipboard, services).
- Background job registry with cancellation support (portscan, socks).

### Important Notes
- `shinject` uses Linux ptrace and requires the agent to have ptrace permissions on the target process.
- `osascript` and `launchctl` are macOS-only. `clipboard`, `getprivs`, and `services` are Windows-only. `cron`, `netstat`, and `shinject` are Linux-only.
- `portscan` and `socks` run as background jobs — use `jobs` to check status and `jobkill` to cancel.

## Authors
@grampae
